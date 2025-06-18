+---------------------------+
| mach_header_64            |   // 文件头，标明这是一个 MH_CORE 类型文件
|   - magic                 |
|   - cputype               |
|   - cpusubtype            |
|   - filetype = MH_CORE    |
|   - ncmds                 |   // load command 数量
|   - sizeofcmds            |   // load command 总大小
+---------------------------+
| load commands (sizeofcmds bytes total)               |
|                                                     |
| 1) LC_THREAD segments (thread 信息)                 |
|   - 1 个或多个，代表每个线程的寄存器状态           |
|                                                     |
| 2) LC_SEGMENT_64 segments (RegionSegment)           |
|   - 每个 region segment 对应内存中的一段数据        |
|   - 包括地址、大小、权限、以及数据                   |
|                                                     |
| 3) LC_NOTE segments (3 个)                           |
|   - "addrable bits" LC_NOTE                          |
|   - "process metadata" LC_NOTE（这里你没完整写，可能是 all image infos）|
|   - "all image infos" LC_NOTE                        |
+-----------------------------------------------------+
| segment data blocks                                  |
| - 真实数据紧跟着 LC_SEGMENT_64 命令的 fileoff       |
| - 包括 thread stacks、region segment 数据            |
+-----------------------------------------------------+
| LC_NOTE 数据块                                      |
| - addrable bits payload                             |
| - process metadata payload (假设)                    |
| - all image infos payload                           |
+-----------------------------------------------------+







mach_header_64
  ├── Load Commands (共 ncmds 个)
  │     ├── LC_THREAD x N（每个线程的寄存器状态）
  │     ├── LC_SEGMENT_64 x M（对应读取到的内存区域，包含多个 RegionSegment）
  │     ├── LC_NOTE x 3 （自定义note段）
  │           ├── LC_NOTE: addrable bits 结构体（version, bits, reserved）
  │           ├── LC_NOTE: process metadata (伪代码中可能扩展)
  │           └── LC_NOTE: all image infos （所有映像信息和它们的段地址等元数据）
  │
  └── 后续数据段
        ├── 各线程的寄存器状态数据（LC_THREAD段对应的数据）
        ├── 各个内存段数据（对应每个LC_SEGMENT_64段的内容，包含dirty页数据）
        └── LC_NOTE段的payload数据（addrable bits数据、all image infos数据等）
