module NmapSU;

redef enum Notice::Type += { UDP_Scan };

global hits: table[addr] of count &default=0;
global notices = 0;

event connection_state_remove(c: connection)
    {
    if ( get_port_transport_proto(c$id$resp_p) != udp || c$conn$conn_state != "S0" )
        return;

    local src = c$id$orig_h;
    hits[src] += 1;

    if ( hits[src] == 50 )
        {
        NOTICE([$note=UDP_Scan, $src=src, $msg=fmt("UDP scan, previous notices: %d", notices)]);
        notices += 1;
        hits[src] = 0;
        }
    }
