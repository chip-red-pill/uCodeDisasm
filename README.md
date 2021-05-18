
# **Disclaimer**

**All information is provided for educational purposes only. Follow these instructions at your own risk. Neither the authors nor their employer are responsible for any direct or consequential damage or loss arising from any person or organization acting or failing to act on the basis of information contained in this page.**

# Content
[Introduction](#introduction)  
[Usage](#Usage)
[The Structure and the Binary Format of Intel Atom Goldmont Microcode](#the-structure-and-the-binary-format-of-intel-atom-goldmont-microcode)  
[Description of Some Important Microoperations](#description-of-some-important-microoperations)  
[Text Labels For Microcode Addresses](#text-labels-for-microcode-addresses)  
[Unresolved Questions](#unresolved-questions) 
[Content of the Publication](#content-of-the-publication) 
[Research Team](#research-eam)  
[License](#license)


# Introduction
Since Intel Atom CPUs are full-fledged, modern representatives of the x86 architecture supporting most of its instruction extensions (Intel VMX, Intel MPX, Intel SGX)  the ability to view, understand and research the microcode of these CPUs is being considered by us as a very important game-changing opportunity in many areas of nowadays security/performance/functional analysis of x86 CPUs. The knowing of the x86 implementation in microcode even for the one representative can greatly empower researchers of the CPU transient execution vulnerabilities because now they can see much deeper what is going on inside one or another x86 instruction implementation and how it affects the microarchitecture (various buffers, registers and internal states). Performance engineers finally can estimate the true latency of Intel CPUs instructions, comparing it with official documentation and Hypervisors developers could see the genuine reason leading to VM exit without relying on numerous guesses. Unfortunately, the Chips Giant has kept this secret with seven seals for over 40 years, but now it seems to emerge.

So last year we managed to extract the microcode for the actual Intel Atom microprocessor having codename Goldmont. We don’t intend to describe the process now, but instead we would like to share our results of the reverse engineering that we’re doing for the Atom’s microcode. Here, we are publishing our microcode disassembler tool using which you can see the interpretation in plain, readable form of the binary microcode which we have already published last year [glm-ucode][4]. Our disassembler is written in Python 3.x script language and prints the binary microoperations together with their text representation (mnemonic + operands). The text translation is done based on our understanding and the progress in the reverse engineering at the current stage, so we don’t claim its absolute certainly. There can be errors as in the microoperation mnemonics naming as well in the arguments representation. Moreover, there still exist unknown operation codes (opcodes) for many microoperations (mostly, for XMM specific), but the basic control flow and ALU opcodes were determined. We encourage all researchers interested in the topic to continue with us the research and extend our disassembler fixing the errors and adding new opcodes. This is one of the goals for the current publication of the microcode disassembler tool intendent for Intel Atom CPUs microcode.

At first glance at the disassembler’s output the researcher may be confused by the naming of some mnemonics especially for microoperations working with physical memory (e.g. LDPPHYSTICKLE_DSZ64_ASZ64_SC1) and he can raise the question of the source for those weird names.  For now, we can say only that those mnemonics were acquired directly from Intel – they published on the one of their official internet resources the raw data representing log files from some microcode simulation tool for certain Big Core microarchitecture. Now, the link isn’t available, but we kept the data which have been subject to deep analysis where we got all those sophisticated mnemonics. By analogy, we invented and our own, where we were not able to find correspondent in the list using the logic and the existing mnemonics as a template. We’re publishing the original list of the opcodes’ mnemonics in separate file (misc/bigcore_opcodes.txt) to let researchers make independent decision about correctness of our choice in the naming and use it for new opcodes.

Next, we will describe the structure of Atom Goldmont microcode and the basic semantic of some most important microoperations. Further, we will describe the remaining unresolved problems which we encountered during our research.


# Usage
```
glm_ucode_disasm.py
Usage: glm_ucode_disasm <ms_array0_file_path>
```

Example:
```
glm_ucode_disasm.py ..\ucode\ms_array0.txt
```

Output listing can be found in 

```
cat ..\ucode\ucode_glm.txt
U0000: 00626803f200                tmp15:= MOVEFROMCREG_DSZ64(CORE_CR_CUR_UIP)
U0001: 000801030008                tmp0:= ZEROEXT_DSZ32(0x00000001)
           018e5e40                SEQW GOTO U0e5e
------------------------------------------------------------------------------------
U0002: 004800013000                tmp7:= ZEROEXT_DSZ64(0x00000000)

U0004: 05b900013000                mm7:= unk_5b9(0x00000000)
U0005: 000a01000200                TESTUSTATE(UCODE, UST_MSLOOPCTR_NONZERO)
           0b000240                ? SEQW GOTO U0002
U0006: 014800000000     SYNCWAIT-> URET(0x00)
------------------------------------------------------------------------------------

U0008: 000c6c97e208                tmp14:= SAVEUIP(0x01, U056c)
           01890900                SEQW GOTO U0909
------------------------------------------------------------------------------------
U0009: 0005a407de08                tmp13:= SUB_DSZ32(0x000001a4, tmp8)
U000a: 01310023d23d                tmp13:= SELECTCC_DSZ32_CONDNZ(tmp13, 0x00000800)

U000c: 00470003dc7d                tmp13:= NOTAND_DSZ64(tmp13, tmp1)
U000d: 0150015c027d   LFNCEWTMRK-> UJMPCC_DIRECT_NOTTAKEN_CONDZ(tmp13, U3701)
U000e: 000000000000                NOP
           06a71180                SEQW GOTO generate_#GP
------------------------------------------------------------------------------------

U0010: 000c6c97e208                tmp14:= SAVEUIP(0x01, U056c)
           0187e100                SEQW GOTO U07e1
------------------------------------------------------------------------------------

sha256_ret:
U0011: 00638e03d200                tmp13:= READURAM(0x008e, 64)
U0012: 00652003e23d                tmp14:= SHR_DSZ64(tmp13, 0x00000020)

U0014: 003d0003df7e                tmp13:= MOVEINSERTFLGS_DSZ32(tmp14, tmp13)
U0015: 00638d03e200                tmp14:= READURAM(0x008d, 64)
U0016: 015d00000ec0                UJMP(tmp11)
```


# The Structure and the Binary Format of Intel Atom Goldmont Microcode

The microcode of the Intel Atom CPUs consists from two large chunks of data – Microcode Triads and Sequence Words. These data are kept in the ROM area of a functional block inside CPU core that is called Microcode Sequencer (MS). We used debug port of MS exposed to CRBUS to extract the data.

Microcode triads represent a set of **three microoperations** which are processed under control of **one sequence word**. The addressing of each microoperation (uop) inside triad are global so the first uop of second triad has address 0x4 (starting from 0x0), where the address 0x3 belongs to non-existing microoperation (an attempt to read the address via the debug port returns zero). In our disassembler we preserved the same addressing scheme because it’s also used in uops performing direct transfer of microcode execution flow. We simply skip each fourth microoperation (don’t print zero data) making a one empty line gap to separate the triads.

Each microoperation of Atom Goldmont microarchitecture has the following 48-bit binary format (at the top here’re the bits indexes, at the bottom – the fields lengths, signs plus mark fields boundaries, vertical bars – bytes):
```
48        44  40        32       24 23    18 16  12    8  6      0
-|--+--+--+----|--------|--------|--+-----+--|----+----|--+------|
 |??|m2|m1|    opcode   |  imm0  |m0| imm1|  dst  | src1  | src0 |
-|--+--+--+----|--------|--------|--+-----+--|----+----|--+------|
   2  1 1      12            8     1   5     6      6       6
```
Where:

**opcode** – 12-bit numeric microoperation code of operation representing the actual operation to perform (all opcodes which we’ve determined are placed in separate file opcodes.txt of our disassembler package)
**src0/src1/dst** – three 6-bits fields which select operands for the operation. You can find the meaning of all numeric selectors for the fields in the disassembler’s python code. For some microoperations, the field dst is actually src2 (represents third source operand, e.g. for memory store uops).

**m0/m1/m2** – there bits representing modes of the operation altering its behavior which are specific for microoperations or to groups of microoperations. E.g. for TESTUSTATE uop (see the description below), bit m0 means NOT, and bits m1 and m2 select various sets of internal state bits to check. For ALU uops (ADD_DSZN, SUB_DSZN and so on), bit m0 allows to select various immediate values representing data of macro-instruction (MACRO IMMS) for which the microcode gets executed.

**imm0/imm1** – represent bits #0-7 and #8-12 of immediate values embedded directly into uops. The bits #13-15 are extracted from the values in src0/src1 field (there’s a set of selectors representing immediate values and containing the last three bits of the values).

**Bits #46 and #47** – present only in ucode patch in RAM area (aren’t set in uops of MSROM) and control some properties of uops substitution which we didn’t determined yet



Each sequence word has the following 30-bit binary format:

```
30 28  25  24 23                    8   6       2   0
-+--+-----+--|--+--------------------+---+-------+---|
 |??|sync | up2 |          uaddr     |up1| eflow |up0|
-+--+-----+--|--+--------------------+---+-------+---|
  2    3     2              15         2     4     2
```
Where:

**up0/up1/up2** – 2-bit pointers to microoperation inside triad. Values 0x0-0x2 point to one of three uops, the value 0x3 has special meaning (see below) for up1 and up2 (for up0 is unacceptable)

**eflow** – 4-bit field that controls execution flow for the microoperations triad. The bit layout of the field can be studied in disassembler’s python code, in **process_seqword** function. The values other than 0x0 imply the use of **up0** field. The value 0x0 (and 0x8-0xb) of eflow field specifies sequential execution of next triad (if up1 has the value 0x3) or the triad at microcode address specified by uaddr field (for up1 values of 0x0:0x2). The **up1** values 0x0:0x2 also point the last uop in the triad to execute (so, in each triad there can be executed less than three uops)

**uaddr** – 15-bit field that specifies the address in microcode ROM (or in patch RAM if uaddr is larger or equal to 0x7c00) for the next triad which accepts execution flow. This field is only applicable for certain values of **eflow** field (see above)

**sync** – 3-bit field that controls two synchronization aspects those apply for microoperations execution which is performed out of order based on dependency chains inside microoperations. Some values specify Load Fences, other specify Synchronization Barriers. See the process_seqword function in Python’s code for exact values. The field is processed (and has meaning) only if up2 field contains 0x0-0x2 values pointing to valid uop inside triad. The value 0x3 for up2 specifies that no sync control is defined inside correspondent triad

**Bits #28-29** – unknown bits defining some undermined aspects of sequence words substitution via Patch RAM (probably, their meaning is the same as for bits #46-47 of uops)


# Description of Some Important Microoperations

## Execution Flow Control uOps

There’re two groups of the most important microoperations:

1. Performing execution flow control of microcode (in addition to that provided by sequence words).
1. Controlling conditional execution of sequence words pertaining to their microcode triads



## SAVEUIP/SAVEUIP_REGOVR/READUIP_REGOVR/URET

We found these mnemonics (SAVEUIP/READUIP/URET) in the original list of opcodes for the Big Core. During the reverse engineering of Atom microcode, we understood that there’re two internal microarchitectural (uarch) registers accessed by the considered uops which allow some kind of procedure calling inside microcode. We named the registers UIP0 and UIP1.

1. SAVEUIP/SAVEUIP_REGOVR – saves the 15-bit value specified inside the uop itself (in IMM0/1 fields of SAVEUIP uop), or uaddr of next microoperation (SAVEUIP_REGOVR) to UIP0/1 register
1. READUIP_REGOVR – reads the current value of  UIP0/1 register into its destination. The REGOVR postfix describes that high 16 bits of 32-bit destination contain the mask for so called uarch register overriding. There’re several selector values for src0/src1/dst fields of uop which select special virtual registers (we named them **tmpv0**, **tmpv1** and so on). These virtual registers can be assigned to point to any uarch register (**tmp0**-**tmp15**) by the Register Override 16-bit value (each 4-bit hex tetrad assigns one of tmp0-tmp15 uarch register for correspondent tmpv0/3 virtual register). After the assignment any uop operating with the tmpv0/3 registers operates actually with correspondent tmp0/15 uarch register
1. URET – perform the transfer of microcode execution flow to uaddr saved previously in UIP0/1 register. The uop argument (0x00 or 0x01) selects one of the two registers.

It must be noted that the procedure calling mechanism allows the branching at most two nesting levels by default.  However, using READUIP_REGOVR/SAVEUIP uops, the microcode can arrange more nesting levels saving and restoring the UIP0/1 values. Also, we note the fact that some eflow control values inside Sequence Words duplicate the functional of the considered uops (there’re control values inside eflow field of sequence words having the same effect on the ucode execution as SAVEUIP/SAVEUIP_REGOVR and URET uops).


## TESTUSTATE/UPDATEUSTATE

One of most sophisticated microoperations which took a long time to understand is the uop for conditional execution of sequence words depending on various microarchitectural internal states and a set of bits which can be manipulated by ucode itself. We named the uop having opcode 0x00a as TESTUSTATE. This microoperation engages all three mode bits (m0/1/2) inside binary format of uop. We found the companion UPDATEUSTATE uop which can set/reset any bit of the internal 6-bit bitmask. This internal 6-bit state can be used in TESTUSTATE uop when m1/m2 bit are both zero. Other combinations of m1/m2 uop modes bits specify internal microarchitectural states to be tested. There’re two sets of the internal uarch states which we named: SYS and VMX states. Our disassembler prints the certain state for each TESTUSTATE uop as first operand. We marked the special case of the 6-bit bitmask manipulated by UPDATEUSTATE uop as UCODE. We investigated and assigned the names at the moment only to first nine SYS states. Among those are: UST_USER_MODE, UST_SMM, UST_VMX_GUEST and others. The VMX internal states are to be determined.
TESTUSTATE microoperation operates as following:

1. If the TESTUSTATE uop is last uop in triad then it defines whether the correspondent Sequence Word is applicable and must be processed. If the condition defined by uop is not met, the triad’s sequence word is skipped and the next triad of uops (uaddr+0x4) gets executed
1. In all other positions inside triad, the TESTUSATE uop duplicates (if the specified condition is met) next one or two uops (they placed into IDQ twice). In our disassembler we mark the conditional sequence words (which belong to tetrads with last TESTUSATE uop) with question sign. We didn’t highlight the other case that is very rare (the reader himself must bear that in mind)
1. The first numeric 16-bit argument (second in the disassembler’s listing) defines which bits in correspondent state/bitmask to check. For all modes except SYS, the set bit in argument checks  whether the correspondent bit in state or bitmask is clear. For SYS mode, the set bit checks that correspondent state (architectural mode) is activated. The mode bit m0 of the uop inverts the rules described above (if m0 is set the TESTUSATE checks the set bits in VMS states/bitmask and that the SYS arch mode is not activated)
1. The modes of the uop are (m2:m1):
   * 0:0  - uop uses internal 6-bit bitmask to test. The bits of the mask can be set/cleared by UPDATEUSTATE uop 
   * 0:1 – uop uses internal SYS states which are mapped to various architectural modes (User Mode, SMM, VMX Non-Root, 64-bit Long Mode and others) 
   * 1:0 – uop uses internal states which we think are connected to VMX implementation in microcode
1. The upper is high level description. To be more precise we describe the source of each bit which we were able to determinate for each mode:
   * UCODE: 0 – special condition that is met until the internal MS loop counter is not zero. Each check of the loop counter by the bit #0 of the uop in UCODE decreases its value. There’s the special uop WRMSLOOPCTRFBR, which sets the initial value for the loop counter
   * UCODE: 1 - undetermined
   * UCODE: 2:7 – the bits of the internal register containing 6-bit bitmask, which can be manipulated by UPDATEUSTATE uop
   * UCODE: 8:15 – the bits 0:7 of the 0x6c3 CRBUS register
   * SYS: 0:7 -  the architectural modes. Each mode is defined by its own architectural method. E.g. User Mode is active only if CPL (the field in CS’s selector) is equal to 3. The TESTUSATE uop tests each arch mode by unique way. There’s no dedicated microarchitectural register or some other thing to define the architectural modes inside microcode – they are defined by the way specified in x86 architecture. The exceptions are SMM mode (and VMX Dual Monitor Treatment mode) which are activated by special CRBUS register with address 0x7c6
   * SYS: 8:12 – the bits 8:12 of the 0x6c3 CRBUS registers
   * SYS: 12 – undetermined
   * SYS: 13:15 – the bits 6:7 of 0x6c5 CRBUS register
   * VMX: 0:15 – scattered bits of 64-bit 0x6c0 register (we didn’t determine the exact match)


## UFLOWCTRL

This very strange microoperation which we ourselves named so can perform (replaces) the functionality of several other uops dealing with execution flow control in particular SAVEUIP, UPDATEUSTATE and some others based on its argument. The full set of uops which the uop can replace see in *get_str_uop_uflow_ctrl_special_imms* function. For the one value of the uop’s argument we were not able to determinate its purpose.

## UJMPCC_DIRECT_NOTTAKEN_CONDX

There exist many uops for conditional operations such as conditional jumps to microcode addresses. They all operate the same way when viewed from the condition part. The condition to test is a part of the microoperation opcode (and mnemonic), but the state to test is not obvious. We determined that execution of all ALU uops doesn’t affect global architectural Flags Register. Yes, there exist special uops to manipulate the Arithmetical Flags of the Flags Registers (e.g. MOVEINSERTFLGS_DSZN in special mode), but where the conditional uops get the state to check was not clear. Eventually, we determined that each microarchitectural register (tmp0-15) has associated set of arithmetical flags, which are assigned **when the register is used as the destination** for any ALU uop. The set of arithmetical flags is independent for each uarch register. There exist several uops to copy the flags between uarch registers (MOVEMERGEFLGS) and even to set the flags in numeric form to any microarchitectural register (MOVEINSERTFLGS_DSZ32). Thus, the conditional uops operate with the arithmetical flags associated with uarch register specified as first source operand. The architectural registers (rax, rbx, rcx and so on) don’t have such association and aren’t used in conditional uops as first operand.

So, i.e. UJMPCC_DIRECT_NOTTAKEN_CONDNZ(tmp0, UXXXX) uop test Zero Flag associated with tmp0 register and transfer the Microcode Sequencer’s execution flow to UXXX addr if the flag is not set, or to uop at next address in microcode otherwise.

All conditional jumps have NOTTAKEN attribute so they aren’t considered as transferring control in speculative execution (behind unresolved branches - other conditional jumps with unresolved source operands). However, the jumps performed by unconditional jumps - due to UJMP, URET uops or by correspondent sequence words processing are always considered as TAKEN.

## SELECTCC_DSZX_CONDX

Conditional selects operate as following: if the flag selected by the condition in opcode is set or clear (depending on the condition) in the associated flags with first source operand, the result of the uop (the value written to destination) is the second source operand else zero.

## CMOVCC_DSZX_CONDX

Conditional moves are similar to conditional selects, but their result is first operand (not second) if the condition is met and the second operand (not zero) if condition is not met. Conditional moves as well as selects have DSZX attribute specifying the size of the destination data.

## CRBUS uops (MOVEFROMCREG_DSZ64 and others)

The Control Register Bus is a fundamental communication mechanism inside CPU core by which all executive units (such as Instruction Fetch Unit, Data Cache Units, Microcode Sequencer, Execution Core and others) send control data between themselves. Each executive unit is connected to CRBUS and exposes its control registers to the bus’s address range.
We used the following naming scheme in our disassembler for the control registers of the executive units (the same scheme is used in internal XML files of Intel DFx Abstraction Layer and Intel OpenIPC software packages):

```<UNIT NAME>_CR_<REG NAME>```

E.g. CORE_CR_CR0 is the control register of the unit performing execution of uops (execution pipline) and contains current value of architectural CR0 register, PMH_CR_CR3 contains architectural page directory physical address in Page Miss Handler unit. Our disassembler supports the assignment of the text names to the control registers via cregs.txt file, where for arbitrary CRBUS address the user can specify arbitrary text name to be used everywhere in disassembler’s listing where uops reference the control register. We determined a set of important CREGs and placed them into the creg.txt file to use in the disassembler.
The microoperations MOVEFROMCREG_DSZ64/ MOVETOCREG_DSZ64 are simples uops to access CRBUS. There also exist a set of MOVETOCREG_BITOPX_DSZ64 uops, which perform the specified bit operation under first source operand and write the result to specified CREG.

## URAM Access uOps

Inside execution pipeline there exist special small random-access memory which is private to each CPU core instance. It has only 512 (0x200) 64-bit entries and is accessed by READURAM/WRITEURAM uops. We called the memory as URAM. The memory isn’t shared by other cores of CPU complex. We are convinced that the memory can be written by arbitrary data and its entries aren’t hardware registers, but it seems that executive units of CPU core can access the URAM independent of microcode. Studying the microcode simulation log files for some Big Core (see Overview chapter) we’ve seen that the Big Cores also have the dedicated small private microarchitectural memory, but they name it as FSCP. We don’t know certainly what the abbreviation means, but decided to name the entries in URAM also as FSCP_CR_XXX. So, in our disassembler package there exist fscp.txt file where the association between arbitrary URAM address and its text name can be set.
There also exist uops performing bit operations on their arguments (by analogy of correspondent CRBUS uops) before the write to URAM, but for now we didn’t determine their mnemonics.

## Text Labels for Microcode Addresses

Our disassembler can assign text label to arbitrary address in microcode, so in all control flow uops, conditional and direct, the text label is used instead UXXX microcode address. The file has name labels.txt and placed nearby main python script. We already filled the file with several labels, which we assigned for different ucode procedures, such as performing  cryptographic procedures and others.
Especially note the labels ending with **_xlat**: they mark entry points for x86 instructions which we determined. XLAT is an abbreviation of “Translate” and underlines that the x86 entry points in ucode are selected by a static tabular mechanism (we’ve seen the same naming of x86 entry points for Big Cores in the ucode emulation log files). Using the ability to execute arbitrary ucode via Match/Patch mechanism (isn’t described in this write-up), we determined many entry points for x86 instructions and placed them into the labels.txt file to be used by researchers.
Even more x86 entries aren’t determined yet. As you can see, each x86 instruction entry in the microcode has the following properties:
1.	The address for any x86 entry point is in the range U0000-U1000
1.	The address for x86 instruction entry must be a multiple of 8
1.	There must not be references in other places of ucode to the x86 entry address

## Unresolved Questions

Our disassembler is far from complete. Here’re the open issues (how we see it) to be implemented:

1. Opcodes and semantic for most SSE uops
Although we found several uops processing MMX/XMM data and implemented the support in our disassembler for mixed uops operating with both MMX/XMM and GP registers (the selectors for the registers in src0/src1/dst fields are overlapped), we didn’t process all SSE microoperations: we added only simple SSE uops those map one to one to correspondent x86 instructions naming them as the instructions (in fact, the mnemonics names for uops may differ). There exist in microcode the procedure for fast SHA256 implementation using vectored SSE data – it almost completely consists from uops with unknown opcodes. That’s a good place to start researching SSE uops.

1.	Two unknown bits for TESTUSTATE
From all possible 48 state bits which can be used in TESTUSTATE uop, only for two of them we don’t know where they are in the microarchitectural state (see description for the TESTUSTATE uop above). We didn’t find bit #1 from UCODE state and bit #13 from SYS state. To understand their meaning, it must be found at first where the bits exist in the microarchitecture (CRBUS, arch state, Fuse, FSCP and so on).

1.	Text names for state bits of TESTUSTATE
We assigned the names for eight most important SYS states of TESTUSTATE uop. You can find the enumeration in Phyton’s function parsing the arguments of the uop (*get_str_uop_xxx_ustate_special_imms*). For remaining seven (one bit is unterminated) SYS states and for VMX states, their purpose must be determined by reverse engineering of microcode changing the states’ sources and appropriate names must be assigned (the Python code has dict for the names to be extended).

1.	Many CRBUS registers
Unfortunately, we don’t have full list of CRBUS registers for Atom Goldmont microarchitecture (we do have the list for some Big Cores that was acquired from XML files of Intel DAL software package). However, the knowing of the Control Registers and their bit layout is very important for complete reverse engineering of the microcode (you will see how much code in MSROM works with CRBUS). We found and added to our disassembler some CRegs using their correlation with MSRs but they are very few of full set.

1.	SIGEVENT numeric argument
This uop is used to raise x86 architectural exceptions. We found (using pure logic) two very important places where #UD and #GP exceptions are generated in microcode using the SIGEVENT uop, but we are not able to map the SIGEVENT argument to x86 exception vector. It seems there’s some other information in the numbers passed to SIGEVENT that must be understood, so the more convenient support for the SIGEVENT uop can be added to our disassembler.

1.	UFLOWCTRL first argument’s value 0x01
We didn’t determinate the purpose of the UFLOWCTRL with first argument’s value of 0x01. It replaces some other uop but it’s unknown which for the argument.

1.	Sequence Word’s UEND variations
We detected among eflow field bits of Sequence Words four values requesting the end of microcode sequencing for current macroinstruction. We marked them as UEND0, UEND1, UEND2 and UEND3. Although we suppose they are indented to deal with out of order execution of uops during the microcode sequencing and perhaps beyond the macroinstruction boundaries the certain purpose of each UENDX is to be determined.

1.	Find an unfixable bug in CPU initialization code
We already found many interesting things using our disassembler, in particular the two undocumented x86 instructions for microarchitectural access, but the main goal remains unresolved: to find a bug in microcode performing CPU initialization from the Reset Entry Point in microcode (U4000) to call of x86 Reset Vector. It’s very probably that a bug in that code flow could not be fixed by microcode patch what makes a precedent of truly unfixable microcode bug and changes the approach of the industry to the microcode implementation.

## Content of the Publication

1.	We publish our microcode disassembler (glm_ucode_disasm), consisting from: 
   * main Python script glm_ucode_disasm.py
   * opcode.txt file with all opcode mnemonics which we determined
   * hard_imm.txt containing all constants from Constants ROM of Atom Goldmont. They are used in uops with special src0/1 selectors
   * Various auxiliary files containing  textual names for several microarchitectural entities (CRBUS regs, URAM entries, labels for microcode addresses)
2.	We publish without any description (who wants to - let him deal with the code) the IDQ (Instruction Decode Queue) processing Python code (*idq_disassemble.py)* with sample test data. IDQ is a key for reverse engineering of the microoperations format and uop opcodes. The code is tightly coupled with disassembler and we don’t want to separate it.
2.	Microoperations opcodes and mnemonics for one of Intel Big Core representative (*misc/bigcore_opodes.txt*)
2.	The full list of all MSRs (*misc/glm_msr_read_desc.txt*, *misc/glm_msr_write_desc.txt*) for Atom Goldmont microarchitecture. MSRs are a bridge between x86 architecture and the microcode, some kind of an interface and they are very important for successfully reverse engineering of microcode. We extracted the two lists of MSR descriptors from special ROM area in uarch (via arbitrary execution of MSR2CR uop), parsed them according to microcode (see *rdmsr_xlat* and *wrmsr_xlat*) and publish the results: for each existing MSR, the following is published: MSR address, applicable modes, the check procedure in microcode, read/write procedure in microcode, address of microarchitectural data for MSR depending of its type (CRBUS regs, URAM regs, hardware register accessed via IO uops, custom MSR composed from many sources). There’re four modes, which affect MSR availability: Normal, SMM, JTAG and ELF (special very privileged x86 code that can exist in microcode update file in encrypted form and gets run directly by microcode). In our MSRs lists, in field Type we mark MSRs by: N (Normal), S (SMM), J (JTAG) and E (ELF).

# Research Team

Mark Ermolov ([@\_markel___][1])

Maxim Goryachy ([@h0t_max][2])

Dmitry Sklyarov ([@_Dmit][3])

# License
Copyright (c) 2021 Mark Ermolov, Dmitry Sklyarov at Positive Technologies and Maxim Goryachy (Independent Researcher)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



[1]: https://twitter.com/_markel___
[2]: https://twitter.com/h0t_max
[3]: https://twitter.com/_Dmit
[4]: https://github.com/chip-red-pill/glm-ucode
