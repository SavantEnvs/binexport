# CMAKE_PROJECT_INCLUDE shim for mayhem/build.sh: reuse an already-built host protoc as protobuf::protoc
# (used with -Dprotobuf_BUILD_PROTOC_BINARIES=OFF so the sanitized tree does not compile libprotoc/protoc).
if(MAYHEM_HOST_PROTOC AND NOT TARGET protobuf::protoc)
  add_executable(protobuf::protoc IMPORTED GLOBAL)
  set_target_properties(protobuf::protoc PROPERTIES IMPORTED_LOCATION "${MAYHEM_HOST_PROTOC}")
endif()
