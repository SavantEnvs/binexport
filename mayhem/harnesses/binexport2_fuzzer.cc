// Copyright 2026 Mayhem integration (additive, not part of upstream BinExport).
//
// Licensed under the Apache License, Version 2.0 (the "License").
//
// In-process libFuzzer harness for google/binexport's BinExport2 parser + the
// disassembly-rendering / reader code paths. It takes bytes ONLY from the fuzzer
// (no file I/O), parses them as a serialized BinExport2 protocol buffer, and then
// exercises exactly the index-heavy code that `binexport2dump` runs when it
// renders a BinExport2 file:
//
//   * RenderExpression() — a byte-for-byte clone of tools/binexport2dump.cc's
//     RenderExpression(): it dereferences attacker-controlled repeated-field
//     indices (proto.expression(operand.expression_index(i))) with NO bounds
//     checks. In a release build protobuf's Get(index) DCHECKs are compiled out,
//     so an out-of-range index is a genuine out-of-bounds read — the exact
//     memory-safety surface a malicious .BinExport2 file attacks.
//   * A full walk of every instruction's mnemonic / operand / expression /
//     comment / string_table index (again the unchecked proto.Get(index) path).
//   * The reader's CallGraph::FromBinExport2Proto() boost-graph builder, guarded
//     against its intentional QCHECK preconditions so the fuzzer spends its budget
//     on real memory-safety defects rather than re-discovering the library's
//     deliberate fatal assertions on malformed input.
//
// The RenderExpression clone below is copied verbatim from
// tools/binexport2dump.cc (same upstream commit), so any crash it produces is an
// upstream crash, not a harness artifact.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/zynamics/binexport/binexport.h"
#include "third_party/zynamics/binexport/binexport2.pb.h"
#include "third_party/zynamics/binexport/reader/call_graph.h"

namespace security::binexport {
namespace {

// Verbatim clone of tools/binexport2dump.cc::RenderExpression (see file header).
void RenderExpression(const BinExport2& proto,
                      const BinExport2::Operand& operand, int index,
                      std::string* output) {
  const int expression_index = operand.expression_index(index);
  const auto& expression = proto.expression(expression_index);
  const auto& expression_symbol = expression.symbol();
  const bool long_mode =
      absl::EndsWith(proto.meta_information().architecture_name(), "64");
  switch (expression.type()) {
    case BinExport2::Expression::OPERATOR: {
      std::vector<int> children;
      children.reserve(4);  // Default maximum on x86
      for (int i = index + 1;
           i < operand.expression_index_size() &&
           proto.expression(operand.expression_index(i)).parent_index() ==
               expression_index;
           ++i) {
        children.push_back(i);
      }
      auto num_children = children.size();
      if (expression_symbol == "{") {  // ARM Register lists
        absl::StrAppend(output, "{");
        for (int i = 0; i < num_children; ++i) {
          RenderExpression(proto, operand, children[i], output);
          if (i != num_children - 1) {
            absl::StrAppend(output, ",");
          }
        }
        absl::StrAppend(output, "}");
      } else if (num_children == 1) {
        absl::StrAppend(output, expression_symbol);
        RenderExpression(proto, operand, children[0], output);
      } else if (num_children > 1) {
        for (int i = 0; i < num_children; ++i) {
          RenderExpression(proto, operand, children[i], output);
          if (i != num_children - 1) {
            const auto& child_expression =
                proto.expression(operand.expression_index(children[i + 1]));
            const auto child_type = child_expression.type();
            if (expression_symbol == "+" &&
                (child_type == BinExport2::Expression::IMMEDIATE_INT ||
                 child_type == BinExport2::Expression::IMMEDIATE_FLOAT)) {
              const int64_t child_immediate =
                  long_mode
                      ? child_expression.immediate()
                      : static_cast<int32_t>(child_expression.immediate());
              if (child_immediate < 0 && child_expression.symbol().empty()) {
                continue;
              }
              if (child_immediate == 0) {
                ++i;  // Skip "+0"
                continue;
              }
            }
            absl::StrAppend(output, expression_symbol);
          }
        }
      }
      break;
    }
    case BinExport2::Expression::SYMBOL:
    case BinExport2::Expression::REGISTER:
      absl::StrAppend(output, expression_symbol);
      break;
    case BinExport2::Expression::SIZE_PREFIX: {
      if ((long_mode && expression_symbol != "b8") ||
          (!long_mode && expression_symbol != "b4")) {
        absl::StrAppend(output, expression_symbol, " ");
      }
      RenderExpression(proto, operand, index + 1, output);
      break;
    }
    case BinExport2::Expression::DEREFERENCE:
      absl::StrAppend(output, "[");
      if (index + 1 < operand.expression_index_size()) {
        RenderExpression(proto, operand, index + 1, output);
      }
      absl::StrAppend(output, "]");
      break;
    case BinExport2::Expression::IMMEDIATE_INT:
    case BinExport2::Expression::IMMEDIATE_FLOAT:
      if (expression_symbol.empty()) {
        const int64_t expression_immediate =
            long_mode ? expression.immediate()
                      : static_cast<int32_t>(expression.immediate());
        if (expression_immediate <= 9) {
          absl::StrAppend(output, expression_immediate);
        } else {
          absl::StrAppend(output, "0x", absl::Hex(expression_immediate));
        }
      } else {
        absl::StrAppend(output, expression_symbol);
      }
      break;
  }
}

// Walk every instruction and render all of its operands/expressions/comments,
// exercising the same unchecked proto.Get(index) accesses binexport2dump makes.
void RenderAllInstructions(const BinExport2& proto) {
  std::string output;
  output.reserve(256);
  for (int i = 0; i < proto.instruction_size(); ++i) {
    const auto& instruction = proto.instruction(i);
    // Mnemonic lookup (out-of-bounds if mnemonic_index is invalid).
    absl::StrAppend(&output,
                    proto.mnemonic(instruction.mnemonic_index()).name(), " ");
    for (int oi = 0; oi < instruction.operand_index_size(); ++oi) {
      const auto& operand = proto.operand(instruction.operand_index(oi));
      for (int j = 0; j < operand.expression_index_size(); ++j) {
        const auto& expression =
            proto.expression(operand.expression_index(j));
        if (!expression.has_parent_index()) {
          RenderExpression(proto, operand, j, &output);
        }
      }
    }
    for (int ci = 0; ci < instruction.comment_index_size(); ++ci) {
      const auto& comment = proto.comment(instruction.comment_index(ci));
      absl::StrAppend(&output, proto.string_table(comment.string_table_index()));
    }
    output.clear();
  }
}

// Touch call-graph vertex / edge index fields the way binexport2dump does.
void RenderCallGraphVertices(const BinExport2& proto) {
  const auto& call_graph = proto.call_graph();
  std::string name;
  for (int i = 0; i < call_graph.vertex_size(); ++i) {
    const auto& vertex = call_graph.vertex(i);
    name = vertex.demangled_name();
    if (name.empty()) name = vertex.mangled_name();
    (void)vertex.address();
    (void)vertex.type();
  }
  for (int i = 0; i < call_graph.edge_size(); ++i) {
    const auto& edge = call_graph.edge(i);
    (void)edge.source_vertex_index();
    (void)edge.target_vertex_index();
  }
}

}  // namespace
}  // namespace security::binexport

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // The BinExport2 proto has no package, so it lives in the GLOBAL namespace.
  using security::binexport::CallGraph;

  ::BinExport2 proto;
  if (!proto.ParseFromArray(data, static_cast<int>(size))) {
    return 0;  // Not a valid BinExport2 serialization — nothing to render.
  }

  security::binexport::RenderAllInstructions(proto);
  security::binexport::RenderCallGraphVertices(proto);

  // Exercise the reader's boost-graph builder, but skip the inputs its own
  // intentional QCHECK preconditions would fatally reject (unsorted vertex
  // addresses) so the fuzzer targets memory-safety defects, not deliberate
  // aborts on malformed protos.
  const auto& cg = proto.call_graph();
  bool sorted = true;
  for (int i = 1; i < cg.vertex_size(); ++i) {
    if (cg.vertex(i - 1).address() > cg.vertex(i).address()) {
      sorted = false;
      break;
    }
  }
  if (sorted) {
    auto call_graph = CallGraph::FromBinExport2Proto(proto);
    (void)call_graph;
  }

  return 0;
}
