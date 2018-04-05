import idaapi

def angr_find_ioctls(bin, dispatch_addr):
	""" Takes a path to a binary and the identified dispatch functions address, attempts to find all valid IOCTL codes
	"""
	
	try:
		import angr
	except:
		print "Please install angr to continue, see: https://github.com/andreafioraldi/angr-win64-wheels"
		return
	
	p = angr.Project(bin, auto_load_libs=False)
	print('loaded binary in angr')
	ioctls = find_ioctls(p, dispatch_addr)
	return ioctls

def find_dispatch(p):
	""" Attempts to find the drivers dispatch function by analysing it's lifted code
	"""
	import pyvex 
	
	cfg = p.analyses.CFGAccurate()
		
	all_vex = [p.factory.block(i.addr).vex for i in cfg.nodes()]
	dispatch_addr = None
	const_seen = False
	for vex in all_vex:
		for stmt in vex.statements:
			const = stmt.constants
			if len(const) > 0:
				if const[0].value == 0x70:
					const_seen = True
			if isinstance(stmt, pyvex.IRStmt.IMark):
				const_seen = False
			if isinstance(stmt, pyvex.IRStmt.Store) and const_seen:
				store_consts = stmt.constants
				if len(store_consts) > 0:
					dispatch_addr = store_consts[0].value
					break
	if not dispatch_addr:
		print "Could not find IOCTL dispatch function :("    
	else:
		print "Dispatch function found: " + hex(dispatch_addr)
	return dispatch_addr
	
def find_ioctls(p, dispatch_addr):
	""" Returns a list of potential IOCTL codes by symbolically executing starting at the provided function address
	"""
	
	import pyvex
	import simuvex
	import claripy
	s = p.factory.blank_state(addr=dispatch_addr)
	pg = p.factory.path_group(s)

	generic_reg_vals = set()
	val_addr = {}
	steps = 0
	while len(pg.active) > 0 and steps < 25:
		for i in pg.active:
				if not idaapi.isLoaded(i.addr):
					print('Non mapped value for addr: {}'.format(hex(i.addr)))
					continue
				print('step: {}, addr: {}'.format(steps, hex(i.addr)))
				for reg in i.state.arch.default_symbolic_registers:
					try:
						val = i.state.se.eval(getattr(i.state.regs, reg))
						#Always use first occurrence
						generic_reg_vals.add(val)
						if val not in val_addr:
							val_addr[val] = i.addr
					except simuvex.SimUnsatError:
						print("failed to get {}".format(reg))
						pass
					except claripy.errors.ClaripyZeroDivisionError:
						print("failed to get {}".format(reg))
						pass
		pg.step()
		steps += 1
	device_codes = {}
		
	generic_reg_vals = filter(lambda x: 0xfff0 > ((x >> 16) & 0xffff) > 0x10, generic_reg_vals)
	for i in generic_reg_vals:
		try:
			device_codes[((i >> 16) & 0xffff)] += 1
		except:
			device_codes[((i >> 16) & 0xffff)] = 1

	if len(device_codes.keys()) == 0:
		return []
	print('potential device codes: {}'.format(device_codes))
	likely_device_code = max(device_codes, key=device_codes.get)
	print "Likely device code: 0x%X" % (likely_device_code,)
	
	out = []
	for i in generic_reg_vals:
		addr = val_addr[i]
		if (i >> 16) & 0xffff == likely_device_code:
			out.append((addr, i))
	return out