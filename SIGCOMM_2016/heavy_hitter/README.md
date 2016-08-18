# Implementing Heavy Hitter Dectection

## Introduction

The objective of this tutorial is to detect the heavy hitters on the network.
Heavy hitters can simply be defined as the traffic sources who send unusually large number of traffic. This can be categories solely by sourhce IP address or can be classified to each application that sends the traffic.
There are various ways to detect and determine the host of the heavy hitter and we will explore two different methods using P4 in this tutaorial.

First method is to use the counters in P4. Counters allow you to keep a measurement of every table match value that occurs in the data plane.
Thus, for every entry in the table, P4 counter keeps a cell to store the counted value in.

The main advantage of using a counter is that it is fairly easy to use and it can give an accurate count of the table entry that we want to count. You can simply specify the counter indices of where the table match should be stored and the counting happens automatically.

However, it comes with couple of disadvantages. Unless we involve the control-plane to add more entries to the table, it is not possible to count for new entries (i.e. unknown flow entries) for the table. Also, it is hard to configure the counter to count on multiple fields of the header at once. Finally, it is also hard to perform any noticable actions or give feedbacks with only the counters and without the help of the control plane.

Therefore, we propose that the attendees of this tutorial to come up a solution that utilizes P4 registers and hashes to perform flexible heavy hitter detection solely on the data plane.

The main idea of the solution is to implement something very similar to counting bloom filter. The idea of the counting bloom filter is to compute multiple hashes of some values and increment the corresponding hash indices of a data structure. In the case of P4, we will use register as the data structure to store the counter values indexed by the hash values. After incrementing the values of the given hash indices,
we can check to see if the new packet is from a heavy hitter by looking at the minimum of the values in the two indices. The image below shows a general idea of how counting bloom filter looks like.

![Alt text](images/counting_bloom_filter.png?raw=true "Counting Bloom Filter")

Given this, we can see that we gain the flexibility of counting on new flows without having to add table entry rules, because the hashes can be computed regardless of the match values. Also, we can see that we can compute the hash based on multiple fields.

This method, however, comes with a disadvantage. Given some certain circumstances where there are many hash collisions, it may not be possible to get the exact count. In our tutorial, this is not an issue, since we only need to identify some connections with a lot of hits.

For our tutorial, we will provide a feedback for detection of heavy hitters by dropping the packets from the heavy hitters. In real world scenario, there are multitude of possible options that you can take to give the feedbacks, such as routing to another hosts and etc.

## Running the starter code

To compile the p4 code under `p4src` and run the switch and the mininet instance, simply run `./run_demo.sh`, which will fire up a mininet instance of 3 hosts (`h1, h2, h3`) and 1 switch (`s1`).
Once the p4 source compiles without error and after all the flow rules has been added, run `xterm h1 h2` on the mininet prompt. It will look something like the below. (If there are any errors at this stage, something is not right. Please let the organizer know as soon as possible.)

```
mininet> xterm h1 h2
```

This will bring up two terminals for two hosts. To test the workflow, run `./receive.py` on `h2`'s window first and `./send.py h2` on `h1`'s window. This will send random flows from `h1` to `h2` with varying sizes and ports. (If interested, please refer to `send.py` to see what kinds of packets are being sent.) If the packet transfer is successful, we can see that packet counts are being made in `h2`'s window for each of the 5 tuples (src ip, dst ip, protocol id, src port, dst port).

After running the flows, run `./read_counter.sh` to view the counter for each host. Note that this script will also reset all counters. We can see that it records the total number of packets from `h1` to `h2`, but lacks any other information. At this stage, you have successfully completed the example program.

## What to do?

Now, we are going to implement the heavy hitter detection based on the counting bloom filter method. In order to dos, there are two files to modify which are the p4 file and `commands.txt`.

First let's discuss what to add in the p4 file. Under `p4src` there is a file called `heavy_hitter_template.p4`. Under this file, places to modify are marked by `TODO`.

The overview of things to complete are as follows.

1. Define constants for determining heavy hitters. For simplicity, let's define a host who sends 1000 or more packets to be the heavy hitter.
2. Update the metadata to contain the hash values and the counter values.
3. Define field_list to compute the hash for the flow. This should basically be the five tuple that we discussed above.
4. Define two separate hashes to generate the hash indices
  * You don't have to worry about writing the hash functions. You can simply use csum16 and crc16. Also, refer to how ipv4_checksum is computed to generate the hash value
5. Define registers with enough space to store the counts
6. Define action to compute the hash, read the current value of the register and update the register as packets come in
  * Hint: You will have to use these primitives. `modify_field_with_hash_based_offset`, `register_read`, `register_write`, `add_to_field`
  * You can choose to write two separate actions or a single action that updates both hashes.
7. Define tables to run the action(s) as defined above.
8. Define tables to drop the table when you detect the heavy hitter.
9. Modify the control flow to apply one table or the other.

After completing this, you must change the name of the file to `heavy_hitter.p4` and overwrite it in `p4src` directory.

Now, we must modify `commands.txt` to remove older table entries and set the defaults for the new tables. We can see that the entries for the older table is now unneeded and can be removed.

After all of this is done. First run `./cleanup` to remove any remnants of the prior run. Then we can again run `./run_demo.sh` to compile the new p4 file, install the new flow rule and open the mininet prompt.

(Note: Mininet can still be running with errors in compilation or switch initalization. Please see the logs that are generated to see if all of the p4 code has been successfully compiled and/or the switch has been configured with the correct table rules). 

We can then generate random traffic as before using the terminals of the two hosts. One thing to notice now is that the traffic will start dropping after the sender reaches more than 1000 packets per five tuple instances. Also note that the traffic is organized by the five tuples rather than a single host, which makes heavy hitter detection much more fine tuned for some specific application.

If all of this works well. Congratulations! You have finished this tutorial.

There are also reference solution in soltion.tar.gz. Feel free to compare your solution to the reference solutions and provie comments and/or updates that can be made to the solution.