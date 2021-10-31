## Specification1: Adding an trace system call. 

* To implement the syscall, I have followed the following steps:
1. Assign the syscall a number in syscall.h
2. Declare the function that syscall internally calls in defs.h and user.h.
3. Implement the syscall in sysproc.c
4. In syscall.c, add the syscall declaration in "syscalls" list of function pointers, "syscalltable" (defined by me for strace command) and in the list of function declarations. 
5. In proc.c, define the function called by the syscall. 
6. Then, add a file, strace.c, which contains the user-level syscall implementation. 
7. Then, add strace to the list of UPROGS in MakeFile.  
8. Add an entry in usys.pl, which generates usys.s, responsible for calling the syscalls.  

* Now, to implement the trace() system call, I have added a new variable in the struct proc, "tr_mask", which is used to indicate whether the system call is to be traced or not.
* Every syscall has to execute the function syscall() in syscall.c. Therefore, for every process, we check if the system call is being traced using the tr_mask variable. If it is, we print information about the system call such as the system call name, the arguments, and the return value.  

## Specification2: Scheduling
- For the scheduler variable to be passed as command line argument, I have made a variable in MakeFile, SCHEDULER, to which we must pass a value among FCFS, MLFQ and PBS (default is RR).   

- **FCFS:** 
1. Add a new variable ctime in the struct proc, which is the time when the process is created.  
2. Then, in scheduler(), from the list of runnable processes, pick the one with the smallest ctime and run it. 
3. Disable timer interrupts in kerneltrap() and usertrap(), enabling the process to run till completion.  

* **Performance:** Average wait time = 62, average run time = 51.

- **PBS:** 
1. First, I implemented the setpriority() system call. 
2. After following the usual steps for adding a general system call, in the setpriority system call, the priority of the process is set to the value of the argument and niceness is reset to 5. Old priority of the process is returned. 
3. Then, for all the list of processes, in scheduler(), the dynamic priority of a process is calculated from it's static priority, niceness values. 
4. Tie-braking rules given in the question are followed. 
5. To calculate niceness, the sleeptime and runtimes of a process are maintained, which are updated after every clock interrupt. 
6. Timer Interrupts were also ignored since it is a non-premptive algorithm. 
7. Sleeping time is interpreted as time spent when process state == SLEEPING. 
8. Also, sleeptime, runtime etc are maintained wrto the last scheduling round. 

* **Performance:** Average wait time = 105 , average run time = 31. 

- **MLFQ:**
1. For, this 5 priority queues were maintained (0-4), with lower levels having higher priority. 
2. Time slices given in the question were followed. wtime (waiting time) variable was created in the struct proc. 
3. First, whenever a process is created, it is inserted into the 0th queue. Then, if a process exceeds its time slice (for that level), it is put into a lower priority queue and then control is given to another process in the same queue. 
4. Whenever a process leaves the queue due to an I/O interrupt and the process comes back, it is inserted in the same queue. 
5. Aging was implemented when a process exceeds the waiting time limit of 40 ticks.  
6. If the process completes, it is removed from the queue. 
7. If all the processes are in the lowest level queue, then the scheduler behaves similar to a round robin scheduler. 
   
Q. If the processes are I/O bound, then they tend to have shorter CPU bursts. This means that they can finish their CPU time in their time slice and move on the I/O queue, meanwhile, the CPU tends to the CPU bound processes. Then, when the I/O bound processes arrive, they are placed in the _same_ priority queue as before and they can again run for their time slice (by preempting CPU bound processes). 

* **Performance:** Average runtime = 0, wait time = 100. 
  
## Specification3: ProcDump
- To implement this for all the schedulers in general, I have maintained a variable rtime in proc struct which calculates the total run time of a process, num_scheduled, giving no of times the process was scheduled, wtime for waiting time. 
- Then, for PBS, I have calculated the priority from its static priority and niceness. 
- For priority for MLFQ, I have retrieved the priority queue in which it is there. 
- For MLFQ, I have also maintained the time spent by the process in each queue. 
- When ctrl+P is pressed, the table is printed.  
