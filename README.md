# sigma
single header signature matching library

usage:
```
sigma::image img = sigma::from_file("c:\\dev\\target_x86.exe");
auto addr = img.matcher()
  .search_hex("b80c0000008be55d")
  .search_procedure_start()
  .offset();

auto addr2 = img.matcher()
  .search_hex("b80c0000008be55d")
  .search_procedure_start()
  .search_hex("b9????????")
  .read<uint32_t>(1));
```
