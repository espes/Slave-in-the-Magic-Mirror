# Python ARMv7 Emulator
#
# Adapted from Javascript ARMv7 Emulator
#
# Copyright 2012, Ryota Ozaki
# Copyright 2014, espes
#
# Licensed under GPL Version 2 or later
#

class Options(object):
	def __init__(self):
		self.enable_stopper = False;
		self.enable_logger = False;
		self.enable_tracer = False;
		self.enable_branch_tracer = False;
		self.logger_buffering = True;
		self.log_size = 1000;
		self.trace_size = 1000;
		self.trace_check_size = 10;
		self.tracer_buffering = True;
		self.branch_trace_size = 1000;
		self.branch_tracer_buffering = True;
		self.stop_counter = None;
		self.stop_instruction = None;
		self.stop_address = None;
		self.stop_at_every_branch = False;
		self.stop_at_every_funccall = False;
		self.update_current_function = False;
		self.suppress_interrupts = False;
		self.show_act_on_viraddr = None;
		self.enable_instruction_counting = False;