FROM ubuntu:20.04

RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" \
	apt install -y gcc-9 \
					make \
					libopenmpi-dev \
					libtalloc-dev \
					libdwarf-dev \
					python3 \
					tar \
					wget \
					vim \
					git \
					python3-pip


# Install OpenSSL
WORKDIR /tmp
RUN wget -O - -nv "https://www.openssl.org/source/openssl-1.1.1h.tar.gz" 2>/dev/null | tar xzv > /dev/null
WORKDIR /tmp/openssl-1.1.1h
RUN ./config 2>/dev/null && \
	make -j 2>/dev/null && \
	make -j install 2>/dev/null

# Install PySRP dep
RUN pip3 install six

# Install sexpect (used inside poc.sh)
RUN git clone https://github.com/clarkwang/sexpect.git /tmp/sexpect && \
    make -C /tmp/sexpect && \
    cp /tmp/sexpect/sexpect /usr/bin/

# Get the rockyou dictionary 
RUN wget -O - -nv https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz?raw=true | gunzip > /usr/share/dict/rockyou.txt

# Install PoC material (spy, parser, dictionary reducer)
COPY ./PoC_material /tmp/PoC_material/
WORKDIR /tmp/PoC_material/
RUN make -C dict_reducer/; \
	chmod +x spy/FR-trace spy/run_spy.sh trace_parser.py dict_reducer/dict_reducer; \
	mv spy/FR-trace spy/run_spy.sh trace_parser.py dict_reducer/dict_reducer /usr/local/bin/; \
	mkdir -p /PoC_PARASITE; \
	cp -r poc.sh /PoC_PARASITE/; 

# Install PySRP and SRP simulator
COPY ./pysrp /tmp/pysrp
RUN	cp -r SRP_simulator/attack_srp.py /PoC_PARASITE/; \
	cp -r ../pysrp/srp/_ctsrp.py /PoC_PARASITE/; \
	ldconfig;

WORKDIR /PoC_PARASITE
