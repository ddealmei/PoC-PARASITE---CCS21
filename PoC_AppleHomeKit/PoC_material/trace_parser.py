#! /usr/bin/python3.8

from sys import argv
import re
import os


class Trace(object):
	"""docstring for trace"""
	def __init__(self, trace, threshold=120):
		self.trace = trace
		self.chunks = []
		self.trimmed_chunks = []
		self.nb_chunks = 0
		self.diff = []
		self.threshold = threshold
		self.get_chunks()

	def get_chunks(self, min_chunk_len=3):
		nb_chunks = self.trace.count('R')
		chunks =[-1 for i in range(nb_chunks)]
		i = nb_chunks - 1
		for c in self.trace:
			if c == 'R':
				i -= 1
			else:
				chunks[i] += 1
		# Some heuristics to remove obviously invalid traces
		for c in chunks:
			if c > 20:
				raise ValueError(f"Error: Unexpected chunks number, very unlikely to be valid ({c}).")
		if nb_chunks < 70:
			raise ValueError(f"Error: Expected more chunks (got {nb_chunks}), trace is probably unusable.")
		if nb_chunks > 100:
			raise ValueError(f"Error: Expected less chunks (got {nb_chunks}), trace is probably unusable.")
		if sum(chunks) > 2000:
			raise ValueError(f"Error: Detected too much operations, trace is probably unusable.")
		if sum(chunks) < 140:
			raise ValueError(f"Error: Detected too few operations, trace is probably unusable.")
		self.nb_chunks = nb_chunks
		self.chunks = chunks

	def get_trace(self):
		print("0102030405060708090A0B0C0D0E0F10,admin," + ",".join([str(x) for x in self.chunks]))


def remove_header(trace):
	for i in range(len(trace)):
		if trace[i].lstrip()[0] != '#':
			return trace[i:]
	return ""

def remove_trailing_operations(trace, threshold = 120):
	for i in range(len(trace)-1, -1, -1):
		if int(trace[i]) < threshold:
			return trace[:i+1]
	return ""

def sanitize_trace(trace):
	t = remove_header(trace)[1:]
	t = remove_trailing_operations(t)
	t = [int(x) for x in t if int(x) != 0]
	return list(reversed(t))

if len(argv) < 2:
	print("Usage: {} TRACE_FILE [...]".format(argv[0]))
	exit()


traces = []
for filename in argv[1:]:
	with open(filename) as fp:
		data = fp.readlines()
	trace_rev = sanitize_trace(data)

	# Replace all value < threshold by x, and other values by 'R'. 
	trace_str = ''.join(['x' if x <= 120 else 'R' for x in trace_rev])
	# Gather close operations into chunks separated by 'R'
	pattern = re.compile("xR{1,4}x")
	new_trace = pattern.sub('xx', trace_str)
	while new_trace != trace_str:
		trace_str = new_trace
		new_trace = pattern.sub('xx', trace_str)

	# Replace R+ strings by a single R to be used as a chunk separator
	pattern = re.compile("R+")
	trace_str = pattern.sub('R', trace_str)

	# We sometimes have a false positive but it is easily visibile as chunks need to be at least 3 'x' long
	pattern = re.compile("Rx{1,2}R")
	trace_str = pattern.sub('R', trace_str)
	if trace_str.startswith('R'):
		trace_str = trace_str[1:]
	try:
		t = Trace(trace_str)
		t.get_trace()
		traces.append(t)
	except Exception as e:
		print(e)
		os.remove(filename)

min_len = min([t.nb_chunks for t in traces])
chunks = [0 for i in range(min_len)]
for t in traces:
	for i in range(1, min_len + 1):
		chunks[-i] += t.chunks[-i]
chunks = [round(x/len(traces)) for x in chunks]
print("0102030405060708090A0B0C0D0E0F10,admin," + ",".join([str(x) for x in chunks]))
