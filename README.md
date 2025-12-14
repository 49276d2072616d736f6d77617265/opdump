# opdump

一個用於**學習與分析**的最小化 ELF64 x86-64 反組譯工具，  
以 **純 C 語言** 撰寫，不依賴任何作業系統或架構專用標頭  
（例如 `elf.h`、`windows.h`、`udis86`、`capstone` 等）。

本專案的目標是**從零開始實作反組譯核心邏輯**，  
透過位元組層級解析指令，作為逆向工程與底層研究的實驗平台。

---

## 目前功能（MVP）

- ELF64 檔案讀取
- `.text` 區段擷取
- x86-64 指令解碼（子集）
- 支援的指令類型：
  - `push` / `pop`
  - `mov`（基本形式）
  - `lea`（基本形式）
  - `xor reg, reg`
  - `call rel32`
  - `jmp rel8 / rel32`
  - 條件跳轉（`jcc`）
  - `ret`
- 未支援的指令以 `db`（raw bytes）顯示
- Intel 語法輸出
- 可反組譯自身的 ELF 可執行檔

> ⚠️ 本工具仍處於 **MVP 階段**，並非完整反組譯器。

---

## 編譯方式
```bash
make
````

---

## 使用方式

```bash
./build/opdump <elf_binary>
```

範例輸出：

```
00000000000011a4  41 57           push r15
00000000000011a6  41 56           push r14
00000000000011c6  31 c0           xor rax, rax
00000000000011cb  0f 8e 79 02 00 00  jle 0x144a
```

---

## 專案定位

* 本專案**不是**為了取代現有反組譯工具
* 專注於：

  * 指令解碼原理
  * opcode / ModRM / REX / 相對位移解析
  * 逆向工程與底層學習用途
* 不包含：

  * 自動控制流程分析
  * 反編譯
  * 去混淆或惡意用途功能

---

## 授權

本專案採用 **MIT License**。
可自由使用、修改、散佈與學術研究用途。

---

# opdump

A minimal ELF64 x86-64 disassembler for **study and analysis**.

Written in **pure C**, without relying on any OS- or architecture-specific
headers or external disassembly libraries
(e.g. `elf.h`, `windows.h`, Capstone, udis86).

The goal of this project is to **implement a disassembler core from scratch**,
decoding instructions directly at the byte level as a learning and research tool
for reverse engineering and low-level systems analysis.

---

## Current Features (MVP)

* ELF64 file loading
* `.text` section extraction
* x86-64 instruction decoding (subset)
* Supported instructions:

  * `push` / `pop`
  * `mov` (basic forms)
  * `lea` (basic forms)
  * `xor reg, reg`
  * `call rel32`
  * `jmp rel8 / rel32`
  * conditional jumps (`jcc`)
  * `ret`
* Unsupported instructions are shown as `db` (raw bytes)
* Intel syntax output
* Capable of disassembling its own ELF binary

> ⚠️ This tool is currently in **MVP stage** and is not a full disassembler.

---

## Build

```bash
make
```

---

## Usage

```bash
./build/opdump <elf_binary>
```

Example output:

```
00000000000011a4  41 57           push r15
00000000000011a6  41 56           push r14
00000000000011c6  31 c0           xor rax, rax
00000000000011cb  0f 8e 79 02 00 00  jle 0x144a
```

---

## Project Scope

* This project is **not** intended to replace existing disassemblers
* Focuses on:

  * instruction decoding fundamentals
  * opcode / ModRM / REX / relative offset handling
  * educational reverse engineering
* Explicitly out of scope:

  * decompilation
  * advanced control-flow analysis
  * obfuscation or malware tooling

---

## License

This project is released under the **MIT License**
and is free to use, modify, and distribute for research and educational purposes.
