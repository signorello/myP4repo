#include <core.p4>
#include <v1model.p4>

#include "./includes/headers.p4"


/*************************************************************************
************   PARSER  **************************************************
*************************************************************************/

parser MyParser(packet_in pkt, out headers hdr, inout metadata meta, inout standard_metadata_t std_meta){

	const bit<16> ETHERTYPE_IPV4 = 0x0800;
	const bit<8> TCP_PROTO = 0x06;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTO: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
	}

}
	

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	const bit<32> REGISTER_SIZE = 1000;
	register<bit<8>>(REGISTER_SIZE) flow_status;
	bit<32> flow_index = 0;
	

	action forward( bit<9> port ){

		standard_metadata.egress_spec = port;

	}

	action update_drop( bit<8> next_state ) {

		flow_status.write( flow_index, next_state );

		mark_to_drop();
		
	}
	
	table transition_table {

	    key = {
		  meta.flow_status : exact;
		  hdr.tcp.dstPort : ternary;
	    }

	    actions =  {
		  update_drop;
		  forward;
	    }

		default_action = update_drop(0x00);

	}

    apply {


		if ( hdr.ipv4.isValid() && hdr.tcp.isValid() ){

			// extern void hash<O, T, D, M>(out O result, in HashAlgorithm algo, in T base, in D data, in M max);
        	hash(flow_index, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr}, (bit<32>)REGISTER_SIZE);

			// load the status in which this specific flow is
			flow_status.read( meta.flow_status, flow_index );

    		// according to the flow status and the tcp dst port, apply a transition
    		transition_table.apply();

  		}
	}

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************      
***********************  D E P A R S E R  ******************************* 
*************************************************************************/      
                                             
control MyDeparser(packet_out pkt, in headers hdr) { 
    apply {  
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.tcp);
    } 
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
