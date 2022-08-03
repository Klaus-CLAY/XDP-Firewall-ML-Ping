#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <linux/types.h>
#include <time.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <fcntl.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include <bpf.h>
#include <libbpf.h>

#include "xdpfw.h"
#include "config.h"
#include "cmdline.h"

// Other variables.
static __u8 cont = 1;
static int filtersmap = -1;
static int statsmap = -1;

void signalHndl(int tmp)
{
    cont = 0;
}

/**
 * Updates the filter's BPF map.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
*/
void updatefilters(struct config *cfg)
{
    // Loop through all filters and delete the map.
    for (__u8 i = 0; i < MAX_FILTERS; i++)
    {
        __u32 key = i;

        bpf_map_delete_elem(filtersmap, &key);
    }

    // Add a filter to the filter maps.
    for (__u32 i = 0; i < MAX_FILTERS; i++)
    {
        // Check if we have a valid ID.
        if (cfg->filters[i].id < 1)
        {
            break;
        }

        // Attempt to update BPF map.
        if (bpf_map_update_elem(filtersmap, &i, &cfg->filters[i], BPF_ANY) == -1)
        {
            fprintf(stderr, "Error updating BPF item #%d\n", i);
        }
    }
}

/**
 * Retrieves an update from the config.
 * 
 * @param cfg A pointer to the config structure.
 * @param cfgfile The path to the config file.
 * 
 * @return 0 on success or -1 on error.
*/
int updateconfig(struct config *cfg, char *cfgfile)
{
    // Open config file.
    if (opencfg(cfgfile) != 0)
    {
        fprintf(stderr, "Error opening filters file: %s\n", cfgfile);
        
        return -1;
    }

    setcfgdefaults(cfg);

    for (__u16 i = 0; i < MAX_FILTERS; i++)
    {
        cfg->filters[i] = (struct filter) {0};
    }

    // Read config and check for errors.
    if (readcfg(cfg) != 0)
    {
        fprintf(stderr, "Error reading filters file.\n");

        return -1;
    }

    return 0;
}

/**
 * Finds a BPF map's FD.
 * 
 * @param bpf_obj A pointer to the BPF object.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
*/
int findmapfd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", mapname);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}

/**
 * Loads a BPF object file.
 * 
 * @param filename The path to the BPF object file.
 * 
 * @return BPF's program FD.
*/
int loadbpfobj(const char *filename, __u8 offload, int ifidx)
{
    int fd = -1;

    // Create attributes and assign XDP type + file name.
    struct bpf_prog_load_attr attrs = 
    {
		.prog_type = BPF_PROG_TYPE_XDP,
	};

    // If we want to offload the XDP program, we must send the ifindex item to the interface's index.
    if (offload)
    {
        attrs.ifindex = ifidx;
    }
    
    attrs.file = filename;

    // Check if we can access the BPF object file.
    if (access(filename, O_RDONLY) < 0) 
    {
        fprintf(stderr, "Could not read/access BPF object file :: %s (%s).\n", filename, strerror(errno));

        return fd;
    }

    struct bpf_object *obj = NULL;
    int err;

    // Load the BPF object file itself.
    err = bpf_prog_load_xattr(&attrs, &obj, &fd);

    if (err) 
    {
        fprintf(stderr, "Could not load XDP BPF program :: %s.\n", strerror(errno));

        return fd;
    }

    struct bpf_program *prog;

    // Load the BPF program itself by section name and try to retrieve FD.
    prog = bpf_object__find_program_by_title(obj, "xdp_prog");
    fd = bpf_program__fd(prog);

    if (fd < 0) 
    {
        printf("XDP program not found by section/title :: xdp_prog (%s).\n", strerror(fd));

        return fd;
    }

    // Retrieve BPF maps.
    filtersmap = findmapfd(obj, "filters_map");
    statsmap = findmapfd(obj, "stats_map");

    return fd;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param ifidx The index to the interface to attach to.
 * @param progfd A file description (FD) to the BPF/XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
 */
int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    char *smode;

    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    __u32 mode = XDP_FLAGS_DRV_MODE;

    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_FLAGS_HW_MODE;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_FLAGS_SKB_MODE;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        err = bpf_set_link_xdp_fd(ifidx, progfd, flags);

        if (err || progfd == -1)
        {
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    errmode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    errmode = "DRV/native";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";

                    break;
            }

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", errmode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                smode = (mode == XDP_FLAGS_HW_MODE) ? "HW/offload" : (mode == XDP_FLAGS_DRV_MODE) ? "DRV/native" : (mode == XDP_FLAGS_SKB_MODE) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);

            break;
        }
    }

    return mode;
}

int main(int argc, char *argv[])
{
    // Parse the command line.
    struct cmdline cmd = 
    {
        .cfgfile = "/etc/xdpfw/xdpfw.conf",
        .help = 0,
        .list = 0,
        .offload = 0
    };

    parsecommandline(&cmd, argc, argv);

    // Check for help menu.
    if (cmd.help)
    {
        fprintf(stdout, "Usage:\n" \
            "--config -c => Config file location (default is /etc/xdpfw/xdpfw.conf).\n" \
            "--offload -o => Tries to load the XDP program in hardware/offload mode.\n" \
            "--skb -s => Force the XDP program to load with SKB mode instead of DRV.\n" \
            "--time -t => How long to run the program for in seconds before exiting. 0 or not set = infinite.\n" \
            "--list -l => Print config details including filters (this will exit program after done).\n" \
            "--help -h => Print help menu.\n");

        return EXIT_SUCCESS;
    }

    // Raise RLimit.
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        fprintf(stderr, "Error setting rlimit.\n");

        return EXIT_FAILURE;
    }

    // Check for --config argument.
    if (cmd.cfgfile == NULL)
    {
        // Assign default.
        cmd.cfgfile = "/etc/xdpfw/xdpfw.conf";
    }

    // Initialize config.
    struct config cfg = {0};

    setcfgdefaults(&cfg);
    
    // Create last updated variable.
    time_t lastupdated = time(NULL);
    time_t statslastupdated = time(NULL);

    // Update config.
    updateconfig(&cfg, cmd.cfgfile);

    // Check for list option.
    if (cmd.list)
    {
        fprintf(stdout, "Details:\n");
        fprintf(stdout, "Interface Name => %s\n", cfg.interface);
        fprintf(stdout, "Update Time => %d\n", cfg.updatetime);

        for (uint16_t i = 0; i < MAX_FILTERS; i++)
        {
            if (cfg.filters[i].id < 1)
            {
                break;
            }

            fprintf(stdout, "Filter #%d:\n", (i + 1));

            // Main.
            fprintf(stdout, "ID => %d\n", cfg.filters[i].id);
            fprintf(stdout, "Enabled => %d\n", cfg.filters[i].enabled);
            fprintf(stdout, "Action => %d (0 = Block, 1 = Allow).\n", cfg.filters[i].action);

            // IP addresses.
            struct sockaddr_in sin;
            sin.sin_addr.s_addr = cfg.filters[i].srcip;
            fprintf(stdout, "Source IP => %s\n", inet_ntoa(sin.sin_addr));

            struct sockaddr_in din;
            din.sin_addr.s_addr = cfg.filters[i].dstip;
            fprintf(stdout, "Destination IP => %s\n", inet_ntoa(din.sin_addr));

            // Other IP header information.
            fprintf(stdout, "Max Length => %d\n", cfg.filters[i].max_len);
            fprintf(stdout, "Min Length => %d\n", cfg.filters[i].min_len);
            fprintf(stdout, "Max TTL => %d\n", cfg.filters[i].max_ttl);
            fprintf(stdout, "Min TTL => %d\n", cfg.filters[i].min_ttl);
            fprintf(stdout, "TOS => %d\n", cfg.filters[i].tos);
            fprintf(stdout, "PPS => %llu\n", cfg.filters[i].pps);
            fprintf(stdout, "BPS => %llu\n\n", cfg.filters[i].bps);
            fprintf(stdout, "Block Time => %llu\n\n", cfg.filters[i].blocktime);

            // TCP Options.
            fprintf(stdout, "TCP Enabled => %d\n", cfg.filters[i].tcpopts.enabled);
            fprintf(stdout, "TCP Source Port => %d\n", cfg.filters[i].tcpopts.sport);
            fprintf(stdout, "TCP Destination Port => %d\n", cfg.filters[i].tcpopts.dport);
            fprintf(stdout, "TCP URG Flag => %d\n", cfg.filters[i].tcpopts.urg);
            fprintf(stdout, "TCP ACK Flag => %d\n", cfg.filters[i].tcpopts.ack);
            fprintf(stdout, "TCP RST Flag => %d\n", cfg.filters[i].tcpopts.rst);
            fprintf(stdout, "TCP PSH Flag => %d\n", cfg.filters[i].tcpopts.psh);
            fprintf(stdout, "TCP SYN Flag => %d\n", cfg.filters[i].tcpopts.syn);
            fprintf(stdout, "TCP FIN Flag => %d\n\n", cfg.filters[i].tcpopts.fin);

            // UDP Options.
            fprintf(stdout, "UDP Enabled => %d\n", cfg.filters[i].udpopts.enabled);
            fprintf(stdout, "UDP Source Port => %d\n", cfg.filters[i].udpopts.sport);
            fprintf(stdout, "UDP Destination Port => %d\n\n", cfg.filters[i].udpopts.dport);

            // ICMP Options.
            fprintf(stdout, "ICMP Enabled => %d\n", cfg.filters[i].icmpopts.enabled);
            fprintf(stdout, "ICMP Code => %d\n", cfg.filters[i].icmpopts.code);
            fprintf(stdout, "ICMP Type => %d\n", cfg.filters[i].icmpopts.type);

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Get device.
    int ifidx;

    if ((ifidx = if_nametoindex(cfg.interface)) < 0)
    {
        fprintf(stderr, "Error finding device %s.\n", cfg.interface);

        return EXIT_FAILURE;
    }
    printf("target interface: %s , index: %d\n", cfg.interface, ifidx);

    // XDP variables.
    int progfd;
    const char *filename = "/etc/xdpfw/xdpfw_kern.o";

    // Get XDP's ID.
    progfd = loadbpfobj(filename, cmd.offload, ifidx);

    if (progfd <= 0)
    {
        fprintf(stderr, "Error loading eBPF object file. File name => %s.\n", filename);

        return EXIT_FAILURE;
    }
    
    // Attach XDP program.
    int res = attachxdp(ifidx, progfd, &cmd);

    if (res != XDP_FLAGS_HW_MODE && res != XDP_FLAGS_DRV_MODE && res != XDP_FLAGS_SKB_MODE)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(res), res);

        return EXIT_FAILURE;
    }

    // Check for valid maps.
    if (filtersmap < 0)
    {
        fprintf(stderr, "Error finding 'filters_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    if (statsmap < 0)
    {
        fprintf(stderr, "Error finding 'stats_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    // Update BPF maps.
    updatefilters(&cfg);

    // Signal.
    signal(SIGINT, signalHndl);

    // Receive CPU count for stats map parsing.
    int cpus = get_nprocs_conf();

    unsigned int endTime = (cmd.time > 0) ? time(NULL) + cmd.time : 0;

    while (cont)
    {
        // Get current time.
        time_t curTime = time(NULL);

        // Check if we should end the program.
        if (endTime > 0 && curTime >= endTime)
        {
            break;
        }

        // Check for auto-update.
        if (cfg.updatetime > 0 && (curTime - lastupdated) > cfg.updatetime)
        {
            // Update config.
            updateconfig(&cfg, cmd.cfgfile);

            // Update BPF maps.
            updatefilters(&cfg);
            
            // Update last updated variable.
            lastupdated = time(NULL);
        }

        // Update stats.
        if ((curTime - statslastupdated) > 2 && !cfg.nostats)
        {
            __u32 key = 0;
            struct stats stats[MAX_CPUS];
            //memset(stats, 0, sizeof(struct stats) * MAX_CPUS);

            __u64 allowed = 0;
            __u64 dropped = 0;
            
            if (bpf_map_lookup_elem(statsmap, &key, stats) != 0)
            {
                fprintf(stderr, "Error performing stats map lookup. Stats map FD => %d.\n", statsmap);

                continue;
            }

            for (int i = 0; i < cpus; i++)
            {
                // Although this should NEVER happen, I'm seeing very strange behavior in the following GitHub issue.
                // https://github.com/gamemann/XDP-Firewall/issues/10
                // Therefore, before accessing stats[i], make sure the pointer to the specific CPU ID is not NULL.
                if (&stats[i] == NULL)
                {
                    fprintf(stderr, "Stats array at CPU ID #%d is NULL! Skipping...\n", i);

                    continue;
                }

                allowed += stats[i].allowed;
                dropped += stats[i].dropped;
            }

            fflush(stdout);
            fprintf(stdout, "\rPackets Allowed: %llu | Packets Dropped: %llu", allowed, dropped);
        
            statslastupdated = time(NULL);
        }

        sleep(1);
    }

    // Detach XDP program.
    attachxdp(ifidx, -1, &cmd);

    // Add spacing.
    fprintf(stdout, "\n");

    // Exit program successfully.
    return EXIT_SUCCESS;
}