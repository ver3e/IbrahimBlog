---
title: The Obsidian Optimizer
date: 2025-12-2
draft: false
tags:
  - rev
  - llvm
  - heroCTF
---
## 1. Introduction

![[Pasted image 20251202030150.png]]
The Obsidian Optimizer is a reverse engineering challenge from `heroCTF`. I usually don't solve reverse engineering challenges but this time we cleared cryptography challenges too early so i decided to give this challenge a shot. Shoutout to the author of this challenge, the challenge introduced me to some cool concepts and was fun to solve. In this writeup i will try to give small introduction to LLVM and some important concepts to know before diving into the challenge. Also, for any part of the decompiled code i will share it and remove any unnecessary code to the point that I'm explaining. 

## 2. Understanding LLVM Basics

Before diving into the decompilation, let's understand what LLVM is and why it matters for this challenge.

### What is LLVM?

LLVM (Low Level Virtual Machine) is a compiler infrastructure. When you compile C code with `clang`It goes through these steps:

```
C Source Code (.c)
       ↓
   [Frontend]
       ↓
LLVM IR (.ll)        ← Human readable intermediate representation
       ↓
   [Optimization Passes]  ← THIS IS WHERE THE CHALLENGE LIVES
       ↓
Machine Code

```

### What is LLVM IR?

LLVM IR is a low-level, typed, SSA (Static Single Assignment) representation. Here's a simple example:

```llvm
define i32 @add(i32 %a, i32 %b) {    ; Define function "add" returning i32
entry:                                ; Label for basic block
  %result = add i32 %a, %b           ; Add the two arguments
  ret i32 %result                     ; Return the result
}

```

Key concepts:

- `i32`, `i64` = integer types (32-bit, 64-bit)
- `ptr` = pointer type
- `%name` = local variable (SSA value)
- `@name` = global variable or function
- `define` = function definition
- `declare` = external function declaration

### What are Optimization Passes?
LLVM passes are transformations that run on the IR. They can:

- **Analyze**: Examine the code without modifying it
- **Transform**: Modify the code (optimize, instrument, etc.)

In this challenge, the binary runs **custom passes** that check if our code matches specific patterns.

### What is JIT Compilation?
JIT (Just-In-Time) compilation means compiling code at runtime. Instead of compiling ahead of time, the program:

1. Receives source/IR code
2. Compiles it in memory
3. Executes it immediately

This challenge uses LLVM's ORC JIT to compile and run our code dynamically.

---

## 3. Binary Analysis - The Main Flow
Now let's open the binary in IDA and understand what it does.

### The main() Function

Loading `the_obsidian_optimizer` in IDA and navigating to `main`, we see the high-level flow,
The binary is setting up LLVM's JIT compiler. `InitializeNativeTarget()` tells LLVM "we want to compile for the current machine's architecture (x86-64)". Without this, LLVM wouldn't know what machine code to generate.

```c
    // Step 1: Create the JIT compiler instance
    llvm::orc::LLJITBuilder::create(v60);
    v25 = std::unique_ptr<llvm::orc::LLJIT>::operator*(v51);

```

LLJIT (Lazy JIT) is LLVM's high-level JIT API. It handles all the complexity of compiling IR to machine code. The "Lazy" part means it only compiles functions when they're first called.

```c
    // Step 2: Create two separate "JITDylib" containers
    llvm::orc::LLJIT::createJITDylib(v59, v25, "JD_Secrets");  // First library
    v24 = llvm::Expected<llvm::orc::JITDylib &>::get(v59);

    llvm::orc::LLJIT::createJITDylib(v58, v25, "JD_Sandbox");  // Second library
    v23 = llvm::Expected<llvm::orc::JITDylib &>::get(v59);

```

A "JITDylib" (JIT Dynamic Library) is like a namespace for symbols. The challenge creates TWO separate containers:

- `JD_Secrets`: Will hold the secret IR (with the flag mechanism)
- `JD_Sandbox`: Will hold our user code

This separation is important - our code runs in a "sandbox" but can call functions from "secrets".

```c
    // Step 3: Set up linking order
    llvm::orc::JITDylib::setLinkOrder(v23, v43, 1);

```

This tells the JIT that when `JD_Sandbox` references an undefined symbol (like `swap_me`), it should look in `JD_Secrets` to find it. This is how our code can call the secret functions.

```c
    // Step 4: Load and patch the secret IR
    std::string::basic_string(v69, "src/secret_ir.ll");
    load_ir_file(v36, v69, v7);

    std::string::basic_string(v63, "./flag.txt");
    v18 = patch_secret_flag(v17, v63);

```

The binary loads `src/secret_ir.ll` (the secret LLVM IR file) and then "patches" it. The patching function reads the actual flag from `./flag.txt` and embeds it into the IR. It also generates a random value that will be used for verification.

```c
    // Step 5: Add secret IR to JD_Secrets
    llvm::orc::LLJIT::addIRModule(v34, v25, v24, v33);

```

The patched secret IR is compiled and added to the `JD_Secrets` library. Now all the secret functions are available for our code to call.

```c
    // Step 6: Load user's IR and run the challenge
    load_ir_file(v29, v70, v8);  // Load our valid_pass.c (compiled to IR)

    if (run_pipeline_and_publish(...)) {
        // Success: Install seccomp and run our check() function
        install_seccomp_filter_do_not_reverse();

        llvm::orc::LLJIT::lookup(v57, v25, v23, "check");
        v28 = llvm::cantFail<llvm::orc::ExecutorAddr>(v57);
        Value = llvm::orc::ExecutorAddr::getValue(&v28);

        v21 = Value();  // CALL our check() function
        llvm::errs() << "[+] check() returned " << v21;
    } else {
        llvm::errs() << "[-] Nope\\\\n";
    }
}

```

This is the critical part:

1. Our C code (`valid_pass.c`) is compiled to IR using `clang -O0 -emit-llvm`
2. `run_pipeline_and_publish()` runs the 5 stages on our IR
3. If all stages pass, our `check()` function is JIT-compiled and executed
4. The return value is printed

### The patch_secret_flag() Function

Let's examine how the flag is embedded:

```c
char patch_secret_flag(llvm::Module *module, const std::string &flag_path) {
    // Get the LLVM context (needed for creating LLVM values)
    Context = llvm::Module::getContext(module);

```

**What's happening here?**

Every LLVM operation happens within a "context". The context owns all the types and constants. We need it to create new values.

```c
    // Find the global variable named "g_random_value"
    llvm::StringRef::StringRef(v15, "g_random_value");
    GlobalVariable = llvm::Module::getGlobalVariable(module, v15);

    if (GlobalVariable) {
        // Generate a cryptographically random 64-bit value
        rand_64 = get_rand_64();  // Reads from /dev/urandom

        if (!rand_64) {
            return 0;  // Fail if we couldn't get randomness
        }

        // Create an LLVM constant with this random value
        Int64Ty = llvm::Type::getInt64Ty(Context);
        v7 = llvm::ConstantInt::get(Int64Ty, rand_64);

        // Set this as the initializer for g_random_value
        llvm::GlobalVariable::setInitializer(GlobalVariable, v7);
        llvm::GlobalVariable::setConstant(GlobalVariable, 1);
    }

```

The secret IR has a global variable `@g_random_value` with a placeholder value. This code:

1. Generates a random 64-bit number from `/dev/urandom`
2. Creates an LLVM constant with that value
3. Sets it as the initial value of `g_random_value`
4. Marks it as constant (can't be modified at runtime)

This random value is the "key" we need to retrieve to unlock the flag.

```c

    llvm::StringRef::StringRef(v14, "flag_str");
    v6 = llvm::Module::getGlobalVariable(module, v14);

    if (v6) {
        read_flag_from_file(v16, flag_path);  // Reads ./flag.txt

        // Create an LLVM string constant with the flag
        llvm::StringRef::StringRef(v13, v16);
        String = llvm::ConstantDataArray::getString(Context, v13);

        // Set this as the initializer for flag_str
        llvm::GlobalVariable::setInitializer(v6, String);
    }

    return 1;
}

```

Similarly, the secret IR has `@flag_str` with a placeholder. This reads the real flag from `./flag.txt` and embeds it into the IR.

### The run_pipeline_and_publish() Function

This is where the magic happens:

```c
bool run_pipeline_and_publish(
    llvm::orc::LLJIT &JIT,
    llvm::orc::JITDylib &Secrets,
    llvm::orc::JITDylib &Sandbox,
    std::unique_ptr<llvm::Module> &UserModule,
    std::unique_ptr<llvm::LLVMContext> &Ctx,
    ChallengeState &state
) {
    // Create a function pass manager
    llvm::FunctionPassManager FPM;

    // Add our 5 custom stages
    FPM.addPass(stage1(&state));
    FPM.addPass(stage2(&state));
    FPM.addPass(stage3(&state));
    FPM.addPass(stage4(&state));
    FPM.addPass(stage5(&state));

```

LLVM uses a "pass manager" to organize and run passes. Here, 5 custom passes are added. Each pass receives a pointer to a shared `ChallengeState` object - this is how they communicate with each other.

```c
    // Run all passes on the user's module
    llvm::ModulePassManager MPM;
    MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));
    MPM.run(*UserModule, MAM);

    // Check if all 5 stages passed
    if (!check_state(&state)) {
        return false;  // At least one stage failed
    }

```

The passes run sequentially on every function in our module. After all passes complete, `check_state()` verifies that all 5 flags in `ChallengeState` are set:

```c
bool check_state(ChallengeState *state) {
    return state->stage1_passed &&
           state->stage2_passed &&
           state->stage3_passed &&
           state->stage4_passed &&
           state->stage5_passed;
}

```

```c
    // If all stages passed, add user's module to JD_Sandbox
    llvm::orc::LLJIT::addIRModule(JIT, Sandbox, UserModule);

    return true;
}

```

---

## 4. Discovering the Secret IR
Now let's examine what's in `src/secret_ir.ll`. This file contains the functions our code will interact with.
### Global Variables

```llvm
@flag_str = global [16 x i8] c"Hero{FAKE_FLAG}\\\\00", align 8
@g_random_value = global i64 323232, align 8
@g_table_size = global i64 3, align 8
@jump_table = internal global [4 x ptr] [ptr null, ptr null, ptr null, ptr @get_flag], align 8

```

**Breaking this down:**

1. `@flag_str`: A placeholder for the real flag. At runtime, `patch_secret_flag()` replaces this with the actual flag.
2. `@g_random_value`: A placeholder (323232) that gets replaced with a cryptographically random value. This is the "key" we need.
3. `@g_table_size`: The size is **3**. This is a **trap** lol, The jump table has 4 entries, but this says 3.
4. `@jump_table`: An array of 4 function pointers:
    - Index 0: `null`
    - Index 1: `null`
    - Index 2: `null`
    - Index 3: `@get_flag` ← The function that prints the flag!

### The Factory Chain
The secret IR implements a "factory chain" - each function checks a magic value and returns the next function in the chain.
### secrets_stage0_factory (This is `swap_me`)

```llvm
define i64* @secrets_stage0_factory(i64 %a, i64 %b, i64 %c, i64 %d) {
entry:
  %cmp_1 = icmp eq i64 %a, 1          ; Check: is first arg == 1?
  br i1 %cmp_1, label %next_2, label %bad
next_2:
  %cmp_2 = icmp eq i64 %b, 2          ; Check: is second arg == 2?
  br i1 %cmp_2, label %next_3, label %bad
next_3:
  %cmp_3 = icmp eq i64 %c, 3          ; Check: is third arg == 3?
  br i1 %cmp_3, label %next_4, label %bad
next_4:
  %cmp_4 = icmp eq i64 %d, 4          ; Check: is fourth arg == 4?
  br i1 %cmp_4, label %ok, label %bad
ok:
  %p = bitcast ptr @secrets_stage1_factory to i64*
  ret i64* %p                          ; Return pointer to next factory
bad:
  ret ptr null                         ; Wrong args → return NULL
}

```

This is the entry point. When we call `swap_me(1, 2, 3, 4)`:

- It verifies all 4 arguments are exactly 1, 2, 3, 4
- If correct, returns a pointer to `secrets_stage1_factory`
- If wrong, returns NULL

### secrets_stage1_factory

```llvm
define i64* @secrets_stage1_factory(i64 %a) {
entry:
  %cmp = icmp eq i64 %a, -1           ; Check: is arg == -1?
  br i1 %cmp, label %ok, label %bad
ok:
  %p = bitcast ptr @secrets_stage2_factory to i64*
  ret i64* %p                          ; Return pointer to next factory
bad:
  ret ptr null
}

```

When called with `-1`, returns a pointer to `secrets_stage2_factory`. Otherwise returns NULL.

### secrets_stage2_factory

```llvm
define i64* @secrets_stage2_factory(i64 %magic) {
entry:
  %cmp = icmp eq i64 %magic, 8571976399   ; Check: is arg == 0x1FEEDBEEF?
  br i1 %cmp, label %ok, label %bad
ok:
  %p = bitcast ptr @secrets_read64_at to i64*
  ret i64* %p                              ; Return pointer to data accessor
bad:
  ret ptr null
}

```

The magic number `8571976399` is `0x1FEEDBEEF` in hexadecimal. This is a "leet speak" number (FEEDBEEF) with an extra nibble. When called with this exact value, returns the final data accessor function.

### secrets_read64_at (The Data Accessor)

```llvm
define i64 @secrets_read64_at(i64 %idx) {
entry:
  %cmp = icmp ult i64 %idx, 24        ; Bounds check: idx < 24?
  br i1 %cmp, label %ok, label %bad
ok:
  %is0 = icmp eq i64 %idx, 0
  br i1 %is0, label %r0, label %next_0
r0:
  %v0 = load i64, ptr @g_random_value ; idx=0: return the random value
  ret i64 %v0
next_0:
  %is8 = icmp eq i64 %idx, 8
  br i1 %is8, label %size, label %next_1
size:
  %table_size = load i64, ptr @g_table_size  ; idx=8: return table size (3)
  ret i64 %table_size
next_1:
  %is16 = icmp eq i64 %idx, 16
  br i1 %is16, label %jt, label %bad
jt:
  %jtptr = ptrtoint ptr @jump_table to i64   ; idx=16: return jump table address
  ret i64 %jtptr
bad:
  ret i64 0
}

```

This is like a "getter" function that returns different data based on the index:

- `secrets_read64_at(0)` → Returns `g_random_value` (the random key!)
- `secrets_read64_at(8)` → Returns `g_table_size` (which is 3)
- `secrets_read64_at(16)` → Returns address of `jump_table`

The indices 0, 8, 16 are like byte offsets in a struct.

### get_flag (The Goal!)

```llvm
define void @get_flag(i64 %val) {
entry:
  %v = load i64, ptr @g_random_value  ; Load the random value
  %cmp = icmp eq i64 %val, %v         ; Compare: does arg match random?
  br i1 %cmp, label %show, label %end
show:
  %ptr = getelementptr inbounds [25 x i8], ptr @flag_str, i64 0, i64 0
  call i32 @puts(ptr %ptr)            ; Print the flag
  br label %end
end:
  ret void
}

```

This is the flag printer! It:

1. Loads the random value that was patched in
2. Compares it with the argument we provide
3. If they match, calls `puts()` to print the flag
4. If they don't match, silently returns

**This is our goal**: Call `get_flag` with the correct random value.

### The Complete Chain

Putting it all together, here's the path to the flag:

```
swap_me(1, 2, 3, 4)           → secrets_stage1_factory
secrets_stage1_factory(-1)     → secrets_stage2_factory
secrets_stage2_factory(8571976399) → secrets_read64_at

secrets_read64_at(0)  → random_value
secrets_read64_at(16) → jump_table address

jump_table[3](random_value) → get_flag(random_value) → PRINTS FLAG!

```

---

## 5. Analyzing the Five Stages
Now we need to understand what each stage pass expects from our code.
### Helper Functions

Before diving into stages, let's understand the helper functions they use.

### find_global_where_value_is_stored

```c
llvm::GlobalVariable* find_global_where_value_is_stored(llvm::Value *value) {
    // Iterate through all users of this value
    for (auto user : value->users()) {
        // Is it a load instruction? Recurse on it.
        if (auto *load = dyn_cast<LoadInst>(user)) {
            return find_global_where_value_is_stored(load);
        }

        // Is it a store instruction where our value is the stored operand?
        if (auto *store = dyn_cast<StoreInst>(user)) {
            if (store->getValueOperand() == value) {
                // Get the pointer operand (where we're storing TO)
                llvm::Value *ptr = store->getPointerOperand();

                // Is it a global variable?
                if (auto *gv = dyn_cast<GlobalVariable>(ptr)) {
                    return gv;  // Found it!
                }
            }
        }
    }
    return nullptr;  // Not found
}

```

Given an LLVM value, this function finds which global variable it gets stored to. For example, if we have:

```c
g_result = some_function();
```

And we call `find_global_where_value_is_stored(return_value_of_some_function)`, it returns the `g_result` global variable.

### loop_upper_bound_check and loop_lower_bound_check

```c
bool loop_upper_bound_check(llvm::Loop *loop, int64_t expected) {
    // Get the loop's exit condition
    // Check if it compares against the expected value
    // Returns true if the upper bound matches
}

bool loop_lower_bound_check(llvm::Loop *loop, int64_t expected) {
    // Check if the loop starts at the expected value
    // Returns true if the lower bound matches
}

```

They verify loop bounds. For example:

```c
for (int i = 0; i < 42; i++) { ... }
```

- `loop_lower_bound_check(loop, 0)` → true (starts at 0)
- `loop_upper_bound_check(loop, 42)` → true (ends at 42)

### Stage 1: The Entry Point

```c
llvm::PreservedAnalyses stage1::run(
    llvm::Function *func,
    llvm::AnalysisManager &AM
) {
    // Get loop analysis for this function
    auto &LI = AM.getResult<LoopAnalysis>(func);

    // Iterate through all loops
    for (auto *loop : LI) {
        // Check: Does this loop go from 0 to 42?
        if (!loop_upper_bound_check(loop, 42)) continue;
        if (!loop_lower_bound_check(loop, 0)) continue;

```

**What's Stage 1 looking for?**

First, it wants a loop with bounds `for (i = 0; i < 42; i++)`.

```c
        // Search inside the loop for our pattern
        for (auto *BB : loop->blocks()) {
            for (auto &I : *BB) {
                // Look for a call instruction
                auto *call = dyn_cast<CallBase>(&I);
                if (!call) continue;

                // Is it calling "swap_me"?
                auto *callee = call->getCalledOperand();
                if (callee->getName() != "swap_me") continue;

```

**What's happening?**

Inside the loop, it searches for a call to a function named "swap_me".

```c
                // Check: Is this call at iteration i == 41?
                // (Checks the preceding comparison instruction)

                // Verify arguments are constants 1, 2, 3, 4
                auto *arg0 = dyn_cast<ConstantInt>(call->getArgOperand(0));
                auto *arg1 = dyn_cast<ConstantInt>(call->getArgOperand(1));
                auto *arg2 = dyn_cast<ConstantInt>(call->getArgOperand(2));
                auto *arg3 = dyn_cast<ConstantInt>(call->getArgOperand(3));

                // Check values
                if (arg0->getSExtValue() != 1) continue;
                if (arg1->getSExtValue() != 2) continue;
                // ... etc

```

The call must have constant arguments 1, 2, 3, 4.

```c
                // Find where the result is stored
                auto *stored_global = find_global_where_value_is_stored(call);
                if (!stored_global) continue;

                // SUCCESS! Stage 1 passes
                state->stage1_passed = true;
                state->stage1_global = stored_global->getName();  // Save for stage 2

                llvm::errs() << "[Stage1] succeeded\\\\n";
            }
        }
    }
}

```

The return value of `swap_me` must be stored to a global variable. Stage 1 saves that variable's name for Stage 2 to use.

**Stage 1 Requirements Summary:**

1. Loop from 0 to 42
2. Inside loop: `if (i == 41)` condition
3. Call `swap_me(1, 2, 3, 4)`
4. Store the result to a global variable

**Our Code:**

```c
for (int i = 0; i < 42; i++) {
    if (i == 41) {
        g_s0 = (fn_t)swap_me(1, 2, 3, 4);
    }
}
```

### Stage 2: Following the Chain

```c
llvm::PreservedAnalyses stage2::run(...) {
    // Prerequisites: Stage 1 must have passed
    if (!state->stage1_passed) return PreservedAnalyses::all();
    if (state->stage1_global.empty()) return PreservedAnalyses::all();
```

**What's happening?**

Stage 2 only runs if Stage 1 passed and saved a global name.

```c
    for (auto *loop : LI) {
        // Check: Does this loop go from 0 to 4919?
        if (!loop_upper_bound_check(loop, 4919)) continue;
        if (!loop_lower_bound_check(loop, 0)) continue;

```

Stage 2 wants a loop with bounds `for (j = 0; j < 4919; j++)`. The number 4919 is arbitrary but specific.

```c
        // Search for a load from stage1's global
        for (auto *BB : loop->blocks()) {
            for (auto &I : *BB) {
                auto *load = dyn_cast<LoadInst>(&I);
                if (!load) continue;

                // Is this loading from the global saved by stage 1?
                auto *ptr = load->getPointerOperand();
                auto *gv = dyn_cast<GlobalVariable>(ptr);
                if (!gv) continue;
                if (gv->getName() != state->stage1_global) continue;

```

Inside the loop, Stage 2 looks for a load instruction that reads from the global that Stage 1 saved (e.g., `g_s0`).

```c
                // Check that there's a comparison with -1 nearby
                // (Looking for: if (j == -1) pattern)

                // The loaded value should be CALLED (it's a function pointer)
                for (auto *user : load->users()) {
                    auto *call = dyn_cast<CallBase>(user);
                    if (!call) continue;

                    // Check call argument is -1
                    auto *arg = dyn_cast<ConstantInt>(call->getArgOperand(0));
                    if (arg->getSExtValue() != -1) continue;

```

The loaded function pointer must be called with argument `-1`. This matches the secret IR's `secrets_stage1_factory(-1)`.

```c
                    // Find where THIS loaded value is stored
                    auto *stored_global = find_global_where_value_is_stored(load);
                    if (!stored_global) continue;

                    // SUCCESS! Stage 2 passes
                    state->stage2_passed = true;
                    state->stage2_global = stored_global->getName();  // Save for stage 3

                    llvm::errs() << "[Stage2] succeeded\\\\n";
                }
            }
        }
    }
}

```

**Key Insight:**

Stage 2 saves where the **loaded value** (not the call result) is stored. This is important!

With code like:

```c
g_s1 = (fn_t)(g_tmp1 = g_s0)(-1);
```

The **loaded value** from `g_s0` is stored to `g_tmp1`. So Stage 2 saves "g_tmp1".

**Stage 2 Requirements Summary:**

1. Loop from 0 to 4919
2. A check for `j == -1` (unreachable, but must exist in IR)
3. Load from Stage 1's global (`g_s0`)
4. Call that loaded function pointer with argument `1`
5. Store the loaded value to another global

**Our Code:**

```c
for (long j = 0; j < 4919; j++) {
    if (j == -1) {
        g_dummy = 1;  // Creates the -1 comparison in IR
    }
    if (j == 0) {
        g_s1 = (fn_t)(g_tmp1 = g_s0)(-1);  // Load g_s0, store to g_tmp1, call with -1
    }
}
```

### Stage 3: The Magic Numbers

```c
llvm::PreservedAnalyses stage3::run(...) {
    // Prerequisites: Stage 2 must have passed
    if (!state->stage2_passed) return PreservedAnalyses::all();
    if (state->stage2_global.empty()) return PreservedAnalyses::all();

    for (auto *loop : LI) {
        // Check: Loop from 0xFFFFFFFF to 0x1FFFFFFFF
        // That's 4294967295 to 8589934591 in decimal
        if (!loop_upper_bound_check(loop, 0x1FFFFFFFF)) continue;
        if (!loop_lower_bound_check(loop, 0xFFFFFFFF)) continue;

```

Stage 3 wants a very specific loop with large 64-bit bounds. Note that `0xFFFFFFFF` is the maximum 32-bit unsigned value.

```c
        // Find load from stage2's global
        for (auto *BB : loop->blocks()) {
            for (auto &I : *BB) {
                auto *load = dyn_cast<LoadInst>(&I);
                if (!load) continue;

                if (load->getPointerOperand()->getName() != state->stage2_global)
                    continue;

```

**What's happening?**

Look for a load from the global saved by Stage 2 (e.g., `g_tmp1`).

```c
        // Look for comparisons with magic numbers
        for (auto *user : loaded_value->users()) {
            auto *next = user->getNextNode();
            auto *icmp = dyn_cast<ICmpInst>(next);
            if (!icmp) continue;

            auto *rhs = dyn_cast<ConstantInt>(icmp->getOperand(1));

            // Check for comparison with 0xFEEDBEEF (4277009103)
            if (rhs->getZExtValue() == 4277009103) {
                found_feedbeef = true;
            }

            // Check for comparison with -1 (signed)
            if (rhs->getSExtValue() == -1) {
                found_minus_one = true;
            }
        }

```

Stage 3 looks for two specific comparisons:

1. A comparison with `0xFEEDBEEF` (4277009103) - leet speak!
2. A comparison with `1` (as signed 64-bit)

These are just pattern checks - they don't need to be reachable at runtime.

```c
        // Both comparisons found?
        if (found_feedbeef && found_minus_one) {
            // Find where the loaded value is stored
            auto *stored_global = find_global_where_value_is_stored(load);

            state->stage3_passed = true;
            state->stage3_global = stored_global->getName();  // Save for stage 4

            llvm::errs() << "[Stage3] succeeded\\\\n";
        }
    }
}

```

**Stage 3 Requirements Summary:**

1. Loop from 4294967295 to 8589934591 (0xFFFFFFFF to 0x1FFFFFFFF)
2. Comparison with 4277009103 (0xFEEDBEEF)
3. Comparison with -1
4. Load from Stage 2's global
5. Store that loaded value somewhere

**Our Code:**

```c
for (long k = 4294967295L; k < 8589934591L; k++) {
    if (k == 4277009103L) {  // 0xFEEDBEEF comparison
        g_dummy = 2;
    }
    if (k == -1L) {  // -1 comparison
        g_dummy = 3;
    }
    if (k == 4294967295L) {
        g_tmp2 = g_tmp1;  // Load from g_tmp1, store to g_tmp2
    }
}

```

### Stage 4: Three-Way Split

```c
llvm::PreservedAnalyses stage4::run(...) {
    // Prerequisites
    if (!state->stage3_passed) return;

    // Find loads from stage3's global (g_tmp2)
    // Expect exactly 3 patterns of: load → call → store to global

    int pattern_count = 0;

    for (auto &I : instructions(func)) {
        auto *load = dyn_cast<LoadInst>(&I);
        if (!load) continue;
        if (load->getPointerOperand()->getName() != state->stage3_global)
            continue;

        // For each load from g_tmp2, find a call using it
        for (auto *user : load->users()) {
            auto *call = dyn_cast<CallBase>(user);
            if (!call) continue;

            // Find where the call result is stored
            auto *stored_global = find_global_where_value_is_stored(call);
            if (!stored_global) continue;

            // Save the global name based on pattern order
            switch (pattern_count) {
                case 0: state->stage4_jt = stored_global->getName(); break;   // Offset 168
                case 1: state->stage4_sz = stored_global->getName(); break;   // Offset 136
                case 2: state->stage4_rv = stored_global->getName(); break;   // Offset 104
            }
            pattern_count++;
        }
    }

    if (pattern_count == 3) {
        state->stage4_passed = true;
        llvm::errs() << "[Stage4] succeeded\\\\n";
    }
}

```

**What's happening?**

Stage 4 looks for exactly 3 instances of:

1. Load from Stage 3's global (`g_tmp2`)
2. Call that loaded function with some argument
3. Store the result in a global

The order matters because Stage 5 uses specific offsets.

**Stage 4 Requirements Summary:**

1. Three "load → call → store" patterns using Stage 3's global
2. Each stores to a different global
3. Order determines which global is `g_jt`, `g_sz`, `g_rv`

**Our Code:**

```c
g_rv = (long)(g_tmp2(0));        // Pattern 1: stored to g_rv
g_sz = (int)(long)(g_tmp2(8));   // Pattern 2: stored to g_sz
g_jt = (fn_void_t*)(g_tmp2(16)); // Pattern 3: stored to g_jt

```

### Stage 5: The Final Check

```c
llvm::PreservedAnalyses stage5::run(...) {
    // Prerequisites
    if (!state->stage4_passed) return;

    // Find loops using findLastLoop
    auto *loop = findLastLoop(LI);

    // Check: Loop lower bound must be 0
    if (!loop_lower_bound_check(loop, 0)) return;

    // Inside the loop, look for:
    // 1. Comparison with constant 3 (for the if (m == 3) check)
    // 2. A GEP (GetElementPtr) using the loop variable as index
    // 3. The GEP base must come from loading stage4's g_jt global
    // 4. A call with argument loaded from stage4's g_rv global

```

**What's happening?**

Stage 5 verifies the final loop structure that will call `get_flag`.

**Stage 5 Requirements Summary:**

1. Loop starting at 0
2. Comparison with 3 (the `if (m == 3)` check)
3. Array access using loop variable as index
4. The array base comes from g_jt
5. Call argument comes from g_rv

**Our Code:**

```c
if (g_sz > 0) {  // Wrapper to create separate preheader
    for (long m = 0; m < g_sz; m++) {
        if (m == 3) {
            g_jt[m](g_rv);  // GEP with m as index, call with g_rv
        }
    }
}

```

---

## 6. The Solution Journey

### Initial Attempt
So this code was working and passing the 5 stages but I didn't get the flag. So i had to take a step back and see what did i do wrong.

```c
typedef void* (*fn_t)(long);
typedef void (*fn_void_t)(long);

extern long swap_me(long, long, long, long);

fn_t g_s0, g_s1, g_tmp1, g_tmp2;
fn_void_t* g_jt;
int g_sz;
long g_rv;
volatile long g_dummy;

__attribute__((optnone))
int check() {
    // Stage 1
    for (int i = 0; i < 42; i++) {
        if (i == 41) {
            g_s0 = (fn_t)swap_me(1, 2, 3, 4);
        }
    }

    // Stage 2
    for (long j = 0; j < 4919; j++) {
        if (j == -1) g_dummy = 1;
        if (j == 0) {
            g_s1 = (fn_t)(g_tmp1 = g_s0)(-1);
        }
    }

    // Stage 3
    for (long k = 4294967295L; k < 8589934591L; k++) {
        if (k == 4277009103L) g_dummy = 2;
        if (k == -1L) g_dummy = 3;
        if (k == 4294967295L) {
            g_tmp2 = g_tmp1;
        }
    }

    // Stage 4
    g_rv = (long)(g_tmp2(0));
    g_sz = (int)(long)(g_tmp2(8));
    g_jt = (fn_void_t*)(g_tmp2(16));

    // Stage 5
    if (g_sz > 0) {
        for (long m = 0; m < g_sz; m++) {
            if (m == 3) {
                g_jt[m](g_rv);
            }
        }
    }

    return 0;
}

```
### Debugging?

We added debug output: `return g_sz;` instead of `return 0`. And as a result, `check()` returned 0 This meant `g_sz` was 0, The jump table size should be 3, not 0.
### Root Cause Analysis
Tracing through the code:

1. **Stage 1:** `g_s0 = swap_me(1,2,3,4)` → `g_s0 = secrets_stage1_factory`
2. **Stage 2:** `g_s1 = (g_tmp1 = g_s0)(-1)`
    - `g_tmp1 = g_s0 = secrets_stage1_factory`
    - Call `secrets_stage1_factory(-1)` → returns `secrets_stage2_factory`
    - `g_s1 = secrets_stage2_factory`
3. **Stage 3:** `g_tmp2 = g_tmp1`
    - `g_tmp2 = secrets_stage1_factory` (NOT `secrets_stage2_factory`!)
4. **Stage 4:** `g_tmp2(8)`
    - `secrets_stage1_factory(8)` → returns NULL (wrong argument!)

**The Problem:**
Stage 2 saves where the **loaded value** is stored, not where the **call result** is stored. So stage 3 loads `secrets_stage1_factory` instead of `secrets_stage2_factory`.We never advance through the factory chain properly
### The Problem (ugh)
Looking at the secret IR again:

- `@g_table_size = global i64 3` (size is 3)
- But `@jump_table` has 4 entries, with `get_flag` at index 3
Even if we fixed the chain, our loop `for (m = 0; m < g_sz; m++)` with `g_sz = 3` would only iterate m = 0, 1, 2 - never reaching m = 3. And tbh i think this was a skill issue my side (^人^)
### The Solution
We can't modify the patterns the passes check without breaking them. But we CAN add additional code AFTER the patterns are satisfied
```c
// After all pass patterns are satisfied...

// Manually call through the factory chain using g_s0
fn_t stage2 = (fn_t)g_s0(-1);                    // secrets_stage2_factory
fn_t read64 = (fn_t)stage2(8571976399LL);        // secrets_read64_at
long random_val = (long)read64(0);               // Get the random value
fn_void_t* jt = (fn_void_t*)read64(16);          // Get jump table
jt[3](random_val);                               // Call get_flag with random

```

**Why this works:**

1. The passes run on the IR and check patterns, they're satisfied by our original code
2. After JIT compilation, the code executes top-to-bottom
3. Our manual chain at the end properly advances through all factories
4. We get the real random value and call `get_flag` with it

---

## 7. Final Exploit & Flag

### Final valid_pass.c

```c
typedef void* (*fn_t)(long);
typedef long (*fn_long_t)(long);
typedef void (*fn_void_t)(long);

extern long swap_me(long, long, long, long);

fn_t g_s0;
fn_t g_s1;
fn_long_t g_s2;

fn_t g_tmp1;
fn_t g_tmp2;

fn_void_t* g_jt;
int g_sz;
long g_rv;

volatile long g_dummy;

__attribute__((optnone))
int check() {
    // ========== STAGE 1 ==========
    // Pass requirements: loop 0-42, call swap_me(1,2,3,4) at i==41, store result
    for (int i = 0; i < 42; i++) {
        if (i == 41) {
            g_s0 = (fn_t)swap_me(1, 2, 3, 4);
        }
    }

    // ========== STAGE 2 ==========
    // Pass requirements: loop 0-4919, j==-1 check, load g_s0, call with -1
    for (long j = 0; j < 4919; j++) {
        if (j == -1) {
            g_dummy = 1;
        }
        if (j == 0) {
            g_s1 = (fn_t)(g_tmp1 = g_s0)(-1);
        }
    }

    // ========== STAGE 3 ==========
    // Pass requirements: loop 0xFFFFFFFF-0x1FFFFFFFF, magic comparisons
    for (long k = 4294967295L; k < 8589934591L; k++) {
        if (k == 4277009103L) {
            g_dummy = 2;
        }
        if (k == -1L) {
            g_dummy = 3;
        }
        if (k == 4294967295L) {
            g_tmp2 = g_tmp1;
        }
    }

    // ========== STAGE 4 ==========
    // Pass requirements: 3x load-call-store patterns from g_tmp2
    g_rv = (long)(g_tmp2(0));
    g_sz = (int)(long)(g_tmp2(8));
    g_jt = (fn_void_t*)(g_tmp2(16));

    // ========== STAGE 5 ==========
    // Pass requirements: loop from 0, m==3 check, GEP with g_jt, call with g_rv
    if (g_sz > 0) {
        for (long m = 0; m < g_sz; m++) {
            if (m == 3) {
                g_jt[m](g_rv);
            }
        }
    }

    // ========== FINAL ==========
    // All passes are satisfied above. Now we manually call the correct chain.
    fn_t stage2 = (fn_t)g_s0(-1);                    // secrets_stage2_factory
    fn_t read64 = (fn_t)stage2(8571976399LL);        // secrets_read64_at
    long random_val = (long)read64(0);               // g_random_value
    fn_void_t* jt = (fn_void_t*)read64(16);          // jump_table
    jt[3](random_val);                               // get_flag(random) -> FLAG!

    return 0;
}

int main(void) {
    return 0;
}

```

### Running the Exploit

```bash
$ python3 solve_template.py

[*] Connecting to reverse.heroctf.fr:7000
[+] Opening connection to reverse.heroctf.fr on port 7000: Done
[*] Reading src/valid_pass.c
[*] Sending 1872 bytes of code
[*] Receiving output from server...

=== Binary Output Start ===
[Stage1] succeeded
[Stage2] succeeded
[Stage3] succeeded
[Stage4] succeeded
[Stage5] succeeded
[Stage4] succeeded
Hero{Y0u_dE53rVe_7He_0bS1Di4n_OpT1mIz3R_tI7l3}
[+] check() returned 0
=== Binary Output End ===

```

## THE END
In conclusion, this was great challenge. kudos to author for such a great challenge. See u Soon, AND HAPPY HACKING （づ￣3￣）づ╭❤️～