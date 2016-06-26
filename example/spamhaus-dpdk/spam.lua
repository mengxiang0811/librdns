--package.cpath = package.cpath .. ";./?.a;/home/developer/dpdk/x86_64-native-linuxapp-gcc/lib/?.so.2.1;"
--print(package.cpath)

print("Load the ffi library")

ffi = require 'ffi'

print("Load the lpm library")
llpm = ffi.load('./liblpm_rules.so')

ffi.cdef[[
int lpm_table_init(int socket_id);
int lpm_entry_add(unsigned int ip, int depth, int next_hop, int socketid);
int lpm_entry_lookup(unsigned int ip, int socketid);
int lpm_get_dst_port(struct rte_mbuf *m, int socketid);
int get_lcore();
int poll(struct pollfd *fds, unsigned long nfds, int timeout);
int printf(const char *fmt, ...);
]]

function lpm_table_init(socketid)
	llpm.lpm_table_init(socketid)
end

function lpm_init()
    if llpm == nil then
        print("Load ./liblpm_rules.so error!")
    else
        --setup the LPM table
        lpm_table_init(0)
    end
end

local function sleep(s)
	ffi.C.poll(nil, 0, s * 1000)
end

function llpm_get_dst_port(pkt)
    return llpm.lpm_get_dst_port(pkt, 0)
end

function llpm_entry_add(ip, depth, nh)
	return llpm.lpm_entry_add(ip, depth, nh, 0)
end

function llpm_entry_lookup(ip)
	return llpm.lpm_entry_lookup(ip, 0)
end
