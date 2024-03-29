## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies

BUILT_SOURCES = \
	include/bounds.h \
	include/debug.h \
	include/preprocids.h \
	include/profiler.h \
	include/cpuclock.h \
	include/sf_dynamic_common.h \
	include/sf_dynamic_engine.h \
	include/sf_dynamic_meta.h \
	include/sf_dynamic_preprocessor.h \
	include/sf_dynamic_preproc_lib.c \
	include/sf_dynamic_preproc_lib.h \
	include/sfghash.h \
	include/sfhashfcn.h \
	include/bitop.h \
	include/sf_ip.h \
	include/sf_ip.c \
	include/sf_ipvar.h \
	include/sf_vartable.h \
	include/ipv6_port.h \
	include/sfsnort_dynamic_detection_lib.c \
	include/sfsnort_dynamic_detection_lib.h \
	include/sf_snort_packet.h \
	include/sf_snort_plugin_api.h \
	include/pcap_pkthdr32.h \
	include/stream_api.h \
	include/str_search.h \
	include/sf_types.h

massage_ipv6_headers = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
	    x=`diff $$src_header $$dst_header.new >> /dev/null`; \
	    if test "$$x" != "0"; then \
	        echo "Updating " $$dst_header; \
	        cp $$src_header $$dst_header.new; \
	        sed -e "s/->iph->ip_src/->ip4_header->source/" -e "s/->iph->ip_dst/->ip4_header->destination/" -e "s/->iph->/->ip4_header->/" -e "s/->iph$$/->ip4_header/" -e "s/orig_iph/orig_ip4_header/" $$dst_header.new > $$dst_header; \
	    fi \
	else \
	    echo "Updating " $$dst_header; \
	    cp $$src_header $$dst_header.new; \
	    sed -e "s/->iph->ip_src/->ip4_header->source/" -e "s/->iph->ip_dst/->ip4_header->destination/" -e "s/->iph->/->ip4_header->/" -e "s/->iph$$/->ip4_header/" -e "s/orig_iph/orig_ip4_header/" $$dst_header.new > $$dst_header; \
	fi

massage_headers = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
		x=`diff $$src_header $$dst_header.new >> /dev/null`; \
	    if test "$$x" != "0"; then \
			echo "Updating " $$dst_header; \
			cp $$src_header $$dst_header.new; \
			sed -e "s/Packet /SFSnortPacket /" -e "s/decode\.h/sf_snort_packet.h/" $$dst_header.new > $$dst_header; \
		fi \
	else \
		echo "Updating " $$dst_header; \
		cp $$src_header $$dst_header.new; \
		sed -e "s/Packet /SFSnortPacket /" -e "s/decode\.h/sf_snort_packet.h/" $$dst_header.new > $$dst_header; \
	fi

copy_debug_header = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
	    x=`diff $$src_header $$dst_header.new.new >> /dev/null`; \
	    if test "$$x" != "0"; then \
	        echo "Updating " $$dst_header; \
	        cp $$src_header $$dst_header.new; \
	        sed -e "s/DebugMessageFile = /*_dpd.debugMsgFile = /" -e "s/DebugMessageLine = /*_dpd.debugMsgLine = /" -e "s/; DebugMessageFunc$$/; _dpd.debugMsg/" -e "s/; DebugWideMessageFunc$$/; _dpd.debugWideMsg/" $$dst_header.new > $$dst_header; \
	    fi \
	else \
	    echo "Updating " $$dst_header; \
	    cp $$src_header $$dst_header.new; \
	    sed -e "s/DebugMessageFile = /*_dpd.debugMsgFile = /" -e "s/DebugMessageLine = /*_dpd.debugMsgLine = /" -e "s/; DebugMessageFunc$$/; _dpd.debugMsg/" -e "s/; DebugWideMessageFunc$$/; _dpd.debugWideMsg/" $$dst_header.new > $$dst_header; \
	fi

copy_headers = \
	mkdir -p include; \
	mkdir -p build; \
	if test -f $$dst_header; then \
		x=`diff $$src_header $$dst_header >> /dev/null`; \
	    if test "$$x" != "0"; then \
			echo "Updating " $$dst_header; \
			cp $$src_header $$dst_header; \
		fi \
	else \
		echo "Updating " $$dst_header; \
		cp $$src_header $$dst_header; \
	fi
	
# From main src tree
include/debug.h: $(srcdir)/../debug.h 
	@src_header=$?; dst_header=$@; $(copy_headers)

include/preprocids.h: $(srcdir)/../preprocids.h
	@src_header=$?; dst_header=$@; $(copy_headers)
	
include/profiler.h: $(srcdir)/../profiler.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/cpuclock.h: $(srcdir)/../cpuclock.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/pcap_pkthdr32.h: $(srcdir)/../pcap_pkthdr32.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/bounds.h: $(srcdir)/../bounds.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/ipv6_port.h: $(srcdir)/../ipv6_port.h
	@src_header=$?; dst_header=$@; $(massage_ipv6_headers)

include/sf_types.h: $(srcdir)/../sf_types.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From dynamic-plugins
include/sf_dynamic_common.h: $(srcdir)/../dynamic-plugins/sf_dynamic_common.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_engine.h: $(srcdir)/../dynamic-plugins/sf_dynamic_engine.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_meta.h: $(srcdir)/../dynamic-plugins/sf_dynamic_meta.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_preprocessor.h: $(srcdir)/../dynamic-plugins/sf_dynamic_preprocessor.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From dynamic-plugins/sf_preproc_example
include/sf_dynamic_preproc_lib.c: $(srcdir)/../dynamic-plugins/sf_preproc_example/sf_dynamic_preproc_lib.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_dynamic_preproc_lib.h: $(srcdir)/../dynamic-plugins/sf_preproc_example/sf_dynamic_preproc_lib.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From Utils
include/sfghash.h: $(srcdir)/../sfutil/sfghash.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfhashfcn.h: $(srcdir)/../sfutil/sfhashfcn.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/bitop.h: $(srcdir)/../sfutil/bitop.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_ip.h: $(srcdir)/../sfutil/sf_ip.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_ip.c: $(srcdir)/../sfutil/sf_ip.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_ipvar.h: $(srcdir)/../sfutil/sf_ipvar.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_vartable.h: $(srcdir)/../sfutil/sf_vartable.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From dynamic-plugins/sf_engine/examples
include/sfsnort_dynamic_detection_lib.c: $(srcdir)/../dynamic-plugins/sf_engine/examples/sfsnort_dynamic_detection_lib.c
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sfsnort_dynamic_detection_lib.h: $(srcdir)/../dynamic-plugins/sf_engine/examples/sfsnort_dynamic_detection_lib.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# From dynamic-plugins/sf_engine
include/sf_snort_packet.h: $(srcdir)/../dynamic-plugins/sf_engine/sf_snort_packet.h
	@src_header=$?; dst_header=$@; $(copy_headers)

include/sf_snort_plugin_api.h: $(srcdir)/../dynamic-plugins/sf_engine/sf_snort_plugin_api.h
	@src_header=$?; dst_header=$@; $(copy_headers)

# Stream API/String Searching, massage it to use SFSnortPacket
include/stream_api.h: $(srcdir)/../preprocessors/stream_api.h
	@src_header=$?; dst_header=$@; $(massage_headers)

include/str_search.h: $(srcdir)/../preprocessors/str_search.h
	@src_header=$?; dst_header=$@; $(massage_headers)

INCLUDES = @INCLUDES@ 

if HAVE_DYNAMIC_PLUGINS
SUBDIRS = dynamic-preprocessor dynamic-rule
endif

clean-local:
	rm -rf include build

