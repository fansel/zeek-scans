module NmapST;

redef enum Notice::Type += { Connect_Scan };

global hits: table[addr] of count &default=0;
global notices = 0;

event connection_state_remove(c: connection)
    {
    if ( c$history != "ShAR" )
        return;

    local src = c$id$orig_h;
    hits[src] += 1;

    if ( hits[src] == 100 )
        {
        NOTICE([$note=Connect_Scan, $src=src, $msg=fmt("Connect scan, previous notices: %d", notices)]);
        notices += 1;
        hits[src] = 0;
        }
    }
