# Monitor @770062=0xbc00e: call to BN_mod_mul_montgomery
# PDA on  @750148=0xb7244: inside bn_mul_words
# Use 3 threads for the PDA to achieve better degradation
# Slot size = 10000 (cycles between two outputs)
# Count = 5000 (measures per slot)
# idle = 500 (nb non-hit slot before stopping)
# repetitions = 60000 to have enought time to launch the process to spy
FR-trace -r 60000 -F "$2" -s 10000 -c 5000 -l 500 -i 500 -H -f "$1" -m 770062 -p 3 -t 750148
