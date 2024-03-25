import idaapi
import idc
import idautils

def get_func_args_count(func_ea):
    func_type = idaapi.tinfo_t()
    if not idaapi.get_tinfo(func_type, func_ea):
        return None

    func_data = idaapi.func_type_data_t()
    if not func_type.get_func_details(func_data):
        return None

    return func_data.size()

def show_gfids_functions(args_count=None):
    guard_fids_seg = idaapi.get_segm_by_name("GFIDS")
    if not guard_fids_seg:
        print("GFIDS segment not found.")
        return

    valid_functions = []
    for ea in idautils.Heads(guard_fids_seg.start_ea, guard_fids_seg.end_ea):
        if idc.is_data(idaapi.get_flags(ea)):
            func_rva = idc.get_wide_dword(ea)
            func_ea = func_rva + idaapi.get_imagebase()
            func_name = idc.get_func_name(func_ea)

            if func_name:
                args_count_found = get_func_args_count(func_ea)
                if args_count is None or (args_count_found is not None and args_count_found == args_count):
                    valid_functions.append([func_name, f"0x{func_rva:08X}", str(args_count_found)])

    if valid_functions:
        print("Guard FIDS Functions:")
        print("{:<40} {:<10} {:<10}".format("Function Name", "RVA", "Arguments"))
        print("-" * 60)
        for func in valid_functions:
            print("{:<40} {:<10} {:<10}".format(func[0], func[1], func[2]))
    else:
        print("No valid functions found.")

    return len(valid_functions)

all_functions_count = show_gfids_functions()
print()
specific_args_count = show_gfids_functions(args_count=2)
print(f"\nTotal count of functions with 2 arguments: {specific_args_count}")
print(f"Total count of all functions: {all_functions_count}")
