// Leaks are not the bug class this target fuzzes for; ASan's memory checks and UBSan stay on.
extern "C" int __lsan_is_turned_off() { return 1; }
