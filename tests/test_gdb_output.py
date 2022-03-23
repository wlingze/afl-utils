

output_file = "/home/wlz/lab/fuzz/Fuzzing101/fuzzing_xpdf/output/gdb_output"


script_output = []
with open(output_file) as f:
    script_output = f.readlines()


grep_for = [
    "Crash sample: ",       # 0 crash

    "CLASSIFICATION:",      # 1 classification
    "FAULTING_INSTRUCTION:",  # 2 faulting instruction
    "SHORT_DESCRIPTION:",   # 3 short description
    "MAJOR_HASH",           # 4 major hash
    "MINOR_HASH",           # 5 minor hash

    "STACK_DEPTH:",         # 6 stack depth
    "STACK_FRAME:"          # 7 stack frame
]


class crash_item:
    def __init__(self):
        self.handle_init()
        self.crash_sample = ""
        self.classification = ""
        self.faulting_instruction = ""
        self.short_description = ""
        self.hash = ""
        self.stack_depth = 0
        self.stack_frame = []
    
    def set_item(self, sig, attr):
        self.handle[sig](attr)
    
    def handle_init(self):
        self.handle = [
            self.set_crash_sample,
            self.set_classification,
            self.set_faulting_instruction,
            self.set_short_description, 
            self.set_hash_major, 
            self.set_hash_minor, 
            self.set_stack_depth, 
            self.set_stack_frame, 
        ]
    def set_crash_sample(self, crash):
        self.crash_sample = crash
    def set_classification(self, classification):
        self.classification = classification
    def set_faulting_instruction(self, faulting_instruction):
        self.faulting_instruction = faulting_instruction
    def set_short_description(self, short_description):
        self.short_description = short_description
    def set_hash_major(self, hash_major):
        self.hash += hash_major
    def set_hash_minor(self, hash_minor):
        self.hash += hash_minor
    def set_stack_depth(self, stack_depth):
        self.stack_depth = int(stack_depth)
    def set_stack_frame(self, stack_frame):
        self.stack_frame.append(stack_frame)
    

    

crash_list = []
crash_idxs = 0

for line in script_output:
    line = line.replace("\n", "")
    for i in range(8):
        grep = grep_for[i]
        if grep in line:
            if i == 0:
                crash_list.append(crash_item())
                crash_idxs+=1
            crash_list[crash_idxs-1].set_item(i, line.replace(grep, ""))



for crash in crash_list:
    print(crash.__dict__)
