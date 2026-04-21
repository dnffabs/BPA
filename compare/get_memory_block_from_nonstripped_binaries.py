#!/usr/bin/env python
from __future__ import print_function
import sys
import os
import angr
import networkx as nx
import matplotlib.pyplot as plt
import pyvex
from pathlib import Path
import subprocess
import re
import queue
import claripy
from collections import OrderedDict
import pdb
import json
import capstone
import signal
import csv
import threading
import traceback
import time
import multiprocessing
import gc
import shutil
import psutil

from datetime import datetime

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_DWARF_expr, set_global_machine_arch

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)

csv_error_collect = os.path.join("gt_out_folder", "errors.csv")

def is_elf(file_path):
    with open(file_path, 'rb') as f:
        try:
            elf_file = ELFFile(f)
            if not elf_file.has_dwarf_info():
                print('  file has no DWARF info')
                #free_some_mem_by_gc()
                return False
            # If opening the file as an ELF file doesn't raise an exception,
            # then the file is an ELF file.
            #free_some_mem_by_gc()
            return True
        except:
            #free_some_mem_by_gc()
            # An exception is raised if the file is not an ELF file.
            return False



def print_red(text):
     print("\033[91m" + text + "\033[0m")

def print_cyan(text):
    CYAN = "\033[96m"  # ANSI escape code for cyan text
    RESET = "\033[0m"  # ANSI escape code to reset text formatting

    print(CYAN + text + RESET)

def print_green_bold(text):
    GREEN_BOLD = "\033[1;32m"  # ANSI escape code for green and bold text
    RESET = "\033[0m"  # ANSI escape code to reset text formatting

    print(GREEN_BOLD + text + RESET)

#+++++++++++++++++++++++++++++++++++++GT CODE STARTS ++++++++++++++++++++++++++++++++++++++++++++++

def delete_file(filename):
    # for filename in file_list:
    try:
        os.remove(filename)
        print(f"Deleted: {filename}")
        #free_some_mem_by_gc()
    except OSError as e:
        
        print(f"Error deleting {filename}: {e}")
        #free_some_mem_by_gc()
def file_exists(filename):
    if os.path.exists(filename):
        return True
    else:
        return False 

#given an elffile , it returns three tuples, data_range, rodata_range, bss_range
def get_global_regions(elf_file):
    data_range = None
    rodata_range = None
    bss_range = None
        
    # Iterate over sections
    for section in elf_file.iter_sections():
        if section.name == '.data':
            data_range = (section['sh_addr'], section['sh_addr'] + section['sh_size'])
        elif section.name == '.rodata':
            rodata_range = (section['sh_addr'], section['sh_addr'] + section['sh_size'])
        elif section.name == '.bss':
            bss_range = (section['sh_addr'], section['sh_addr'] + section['sh_size'])
    #free_some_mem_by_gc()
    return data_range, rodata_range, bss_range

def is_elf(file_path):
    with open(file_path, 'rb') as f:
        try:
            elf_file = ELFFile(f)
            if not elf_file.has_dwarf_info():
                print('  file has no DWARF info')
                #free_some_mem_by_gc()
                return False
            # If opening the file as an ELF file doesn't raise an exception,
            # then the file is an ELF file.
            #free_some_mem_by_gc()
            return True
        except:
            # An exception is raised if the file is not an ELF file.
            #free_some_mem_by_gc()
            return False

def process_file(filename, json_db, json_db_globalregion):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return
        data_region_tuple,rodata_range_tuple, bss_range_tuple =  get_global_regions(elffile)
        try:
            json_db_globalregion[0]['start'] = data_region_tuple[0]
            json_db_globalregion[0]['end'] = data_region_tuple[1]
            json_db_globalregion[1]['start'] = rodata_range_tuple[0]
            json_db_globalregion[1]['end'] = rodata_range_tuple[1]
            json_db_globalregion[2]['start'] = bss_range_tuple[0]
            json_db_globalregion[2]['end'] = bss_range_tuple[1]
        except Exception as e:
            #free_some_mem_by_gc()
            append_to_csv(csv_error_collect, ['error while doing the global region start and end update', str(e)])
            print_red("error while doing the global region start and end update")
        
        # global_region_range =[data_region_tuple,rodata_range_tuple, bss_range_tuple]
        # global_region_range.append()
        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()
        # The location lists are extracted by DWARFInfo from the .debug_loc
        # section, and returned here as a LocationLists object.
        location_lists = dwarfinfo.location_lists()
        # Create a LocationParser object that parses the DIE attributes and
        # creates objects representing the actual location information.
        loc_parser = LocationParser(location_lists)
        # print(type(elffile.get_machine_arch()))

        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(elffile.get_machine_arch())

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows iterating over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.
            print('  Found a compile unit at offset %s, length %s' % (
                CU.cu_offset, CU['unit_length']))

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()
            print('    Top DIE with tag=%s' % top_DIE.tag)

            # We're interested in the filename...
            print('    name=%s' % Path(top_DIE.get_full_path()).as_posix())

            csv_path = 'abc.csv'
            process_global_region(csv_path,data_region_tuple,rodata_range_tuple, bss_range_tuple,top_DIE, location_lists, loc_parser, dwarfinfo, CU, elffile.get_machine_arch(),json_db_globalregion,filename,Path(top_DIE.get_full_path()).as_posix())
            # Display DIEs recursively starting with top_DIE
            process_function(data_region_tuple,rodata_range_tuple, bss_range_tuple,top_DIE, location_lists, loc_parser, dwarfinfo, CU, elffile.get_machine_arch(),json_db,filename,Path(top_DIE.get_full_path()).as_posix())
            # #free_some_mem_by_gc()
        #free_some_mem_by_gc()
'''
def process_function(data_region_tuple,rodata_range_tuple, bss_range_tuple,die, location_lists, loc_parser,dwarfinfo,CU, arch,json_db, binary_name, cu_name, indent_level='    '):
    """ A recursive function for showing information about a function DIE and its
        variables.
    """
    if die.tag == 'DW_TAG_subprogram':
        function_name = die.attributes.get('DW_AT_name', None)
        declaration = die.attributes.get('DW_AT_declaration', None)
        flag_declare = False
        if declaration is not None:
            flag_declare = declaration.value
            
        log_total_var = 0
        log_identified_var  = 0
        # if function_name is not None and flag_declare == False:
        if function_name is not None:
            print(indent_level + 'Function: %s' % function_name.value)
            # function_info = {
            #     'name': function_name.value,
            #     'variables': []
            # }
            all_variable_location_list = []
            all_variable_dwarf_list = []
            print(indent_level + '  Variables:', die.has_children)
            for child in die.iter_children():
                print('extra debug--->',child.tag)
                if child.tag == "DW_TAG_lexical_block":
                    # print('-----------> found one')
                    for grand_child in child.iter_children():
                        # print('---->', grand_child.tag)
                        if grand_child.tag == 'DW_TAG_variable':
                            log_total_var += 1
                            variable_name = grand_child.attributes.get('DW_AT_name', None)
                            if variable_name is not None:
                                print(indent_level + '    Variable: %s' % variable_name.value)
                                var_size = process_variable_location(grand_child, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
                                list_lower_upper_var = process_variable_dwarf_loc(grand_child, location_lists, loc_parser, dwarfinfo, CU,arch,var_size,  indent_level + '      ')
                                # print(list_lower_upper_var)
                                l = give_var_location_str(grand_child, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
                                result = ''
                                for element in l:
                                    result += element + ' '

                                # Remove the trailing space
                                result = result.rstrip()
                                all_variable_dwarf_list.append(result)
                                if list_lower_upper_var is not None:
                                    log_identified_var += 1
                                    for i in list_lower_upper_var:
                                        all_variable_location_list.append(i) 
                                else:
                                    all_variable_location_list.append((0,0))
                                # variable_info = {
                                #     'name': variable_name.value,
                                #     'size': var_size,
                                #     'location': list_lower_upper_var,
                                # }
                                # function_info['variables'].append(variable_info)
                # if child.tag == 'DW_TAG_variable' or child.tag == 'DW_TAG_formal_parameter':
                if child.tag == 'DW_TAG_variable':
                    log_total_var += 1
                    variable_name = child.attributes.get('DW_AT_name', None)
                    if variable_name is not None:
                        print(indent_level + '    Variable: %s' % variable_name.value)
                        var_size = process_variable_location(child, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
                        list_lower_upper_var = process_variable_dwarf_loc(child, location_lists, loc_parser, dwarfinfo, CU, arch, var_size, indent_level + '      ')
                        l = give_var_location_str(child, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
                        result = ''
                        for element in l:
                            result += element + ' '

                        # Remove the trailing space
                        result = result.rstrip()
                        all_variable_dwarf_list.append(result)
                        if list_lower_upper_var is not None:
                            for i in list_lower_upper_var:
                                log_identified_var += 1
                                all_variable_location_list.append(i) 
                        else:
                            all_variable_location_list.append((0,0))
                        # variable_info = {
                        #         'name': variable_name.value,
                        #         'size': var_size,
                        #         'location': list_lower_upper_var,
                        #     }
                        # function_info['variables'].append(variable_info)
            json_db.append({
                'filename': os.path.basename(binary_name),
                'compilation_unit': os.path.basename(cu_name),
                'function_name': str(function_name.value)[2:-1],
                'function_loc_list': flaten_sort_list(all_variable_location_list),
                # 'dwarf_strs': all_variable_dwarf_list,
                'arch': arch,
                'total_var' : log_total_var,
                'identified_var': log_identified_var,

            })
    child_indent = indent_level + '  '
    for child in die.iter_children():
        process_function(data_region_tuple,rodata_range_tuple, bss_range_tuple,child,  location_lists, loc_parser, dwarfinfo, CU, arch,json_db,binary_name, cu_name, child_indent)
'''


# def disassemble_function(filename, function_name):
#     try:
#         command = ["./dism.sh", filename, function_name]
#         disassembly_output = subprocess.check_output(command)
#         return disassembly_output.decode("utf-8")
#     except subprocess.CalledProcessError as e:
#         print("Error disassembling function", str(e))
def disassemble_function(filename, function_name):
    """
    Disassemble the entire ELF file using Capstone and return a disassembly string.
    This replacement allows the script to run on Windows.
    """
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            arch = elffile.get_machine_arch()

            # Select Capstone mode
            if arch == 'x86':
                md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif arch == 'x64' or arch == 'AMD64':
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                print(f"[!] Unsupported architecture: {arch}")
                return ""

            # Try to locate the .text section
            text_section = elffile.get_section_by_name('.text')
            if text_section is None:
                print("[!] No .text section found.")
                return ""

            code = text_section.data()
            start_addr = text_section['sh_addr']

            disassembly_output = ""
            for insn in md.disasm(code, start_addr):
                disassembly_output += f"{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n"

            return disassembly_output

    except Exception as e:
        print(f"[!] Error disassembling function {function_name}: {e}")
        return ""

#return two things: first is the presence of the push rbp then the code addresses for the initial instruction else False, None
def identify_first_push_ebp_instruction_return_line_offset(disassembly):
    instruction_list_to_be_visited = []
    for line in disassembly.split('\n'):
        instruction_list_to_be_visited.append(line)
        l = line.split()
        if len(l) == 4:
            if l[1] == '55' and l[2] == 'push' and l[3] == 'ebp':
                return True, l[0], instruction_list_to_be_visited
            
    return False, None , None


#returns two thing , presence of push ebp  and the offset we are 'utf-8'supposed to add extra
def check_presence_of_push_ebp_and_extra_offset_calculation(bin_name_full_path, func_name):
    #use some other function to get the disassembled code and then process it on your own
    extra_offset_subtraction = 0
    disassembly = disassemble_function(bin_name_full_path, func_name)
    ebp_presence, ebp_inst_addr, inst_list_to_ve_visited = identify_first_push_ebp_instruction_return_line_offset(disassembly)
    if ebp_presence == True:
        # extra_offset_subtraction = 4
        for inst in inst_list_to_ve_visited:
            if 'push' in inst:
                extra_offset_subtraction += 4

        return ebp_presence, extra_offset_subtraction
    else:
        #push ebp not found
        return ebp_presence, extra_offset_subtraction
    #identify the push ebp first


def process_function(data_region_tuple, rodata_range_tuple, bss_range_tuple, die, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name, indent_level='    '):
    """A recursive function for showing information about a function DIE and its variables."""
    if die.tag == 'DW_TAG_subprogram':
        function_name = die.attributes.get('DW_AT_name', None)
        declaration = die.attributes.get('DW_AT_declaration', None)
        flag_declare = False
        if declaration is not None:
            flag_declare = declaration.value

        log_total_var = 0
        log_identified_var = 0

        if function_name is not None:
            print(indent_level + 'Function: %s' % function_name.value)
            #task 1.1: june 3: get the push rbp presense and the offsets before the rbp
            ebp_presence,extra_offset_subtraction = check_presence_of_push_ebp_and_extra_offset_calculation(binary_name, function_name.value.decode("utf-8"))

            all_variable_location_list = []
            all_variable_dwarf_list = []
            ebp_offset_list = []
            esp_offset_list = []

            print(indent_level + '  Variables:', die.has_children)
            for child in die.iter_children():
                if child.tag == "DW_TAG_lexical_block":
                    process_lexical_block(all_variable_location_list,child, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list, indent_level + '    ')
                elif child.tag == 'DW_TAG_inlined_subroutine':
                    process_inlined_subroutine(all_variable_location_list,child, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list, indent_level + '    ')

                elif child.tag == 'DW_TAG_variable':
                    log_total_var += 1
                    variable_name = child.attributes.get('DW_AT_name', None)
                    if variable_name is not None:
                        print(indent_level + '    Variable: %s' % variable_name.value)
                        var_size = process_variable_location(child, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
                       
                        list_lower_upper_var = process_variable_dwarf_loc(child, location_lists, loc_parser, dwarfinfo, CU, arch, var_size,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list,  indent_level + '      ')
                        l = give_var_location_str(child, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
                        result = ''
                        for element in l:
                            result += element + ' '

                        result = result.rstrip()
                        all_variable_dwarf_list.append(result)
                        if list_lower_upper_var is not None:
                            for i in list_lower_upper_var:
                                log_identified_var += 1
                                all_variable_location_list.append(i)
                        else:
                            all_variable_location_list.append((0, 0))
            
            json_db.append({
                'filename': os.path.basename(binary_name),
                'compilation_unit': os.path.basename(cu_name),
                'function_name': str(function_name.value)[2:-1],
                'function_loc_list': flaten_sort_list(all_variable_location_list),
                'arch': arch,
                'total_var': log_total_var,
                'identified_var': log_identified_var,
                'ebp_presence': ebp_presence,
                'extra_offset_subtraction': extra_offset_subtraction,
                'ebp_offset_list': ebp_offset_list,
                'esp_offset_list': esp_offset_list,
            })
    child_indent = indent_level + '  '
    for child in die.iter_children():
        process_function(data_region_tuple, rodata_range_tuple, bss_range_tuple, child, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name, child_indent)

def process_lexical_block(all_variable_location_list,block, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list, indent_level):
    """Process a lexical block."""
    for child in block.iter_children():
        if child.tag == "DW_TAG_lexical_block":
            process_lexical_block(all_variable_location_list,child, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list, indent_level)
        elif child.tag == 'DW_TAG_variable':
            # Process variables within the lexical block
            process_variable(all_variable_location_list,child, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list, indent_level)
    # #free_some_mem_by_gc()

def process_variable(all_variable_location_list,variable, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list, indent_level):
    """Process a variable."""
    variable_name = variable.attributes.get('DW_AT_name', None)
    if variable_name is not None:
        print(indent_level + '    Variable: %s' % variable_name.value)
        var_size = process_variable_location(variable, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
        list_lower_upper_var = process_variable_dwarf_loc(variable, location_lists, loc_parser, dwarfinfo, CU, arch, var_size, ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list,indent_level + '      ')
        l = give_var_location_str(variable, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
        # result = ''
        # for element in l:
        #     result += element + ' '

        # result = result.rstrip()
        # all_variable_dwarf_list.append(result)
        if list_lower_upper_var is not None:
            for i in list_lower_upper_var:
                # log_identified_var += 1
                all_variable_location_list.append(i)
        else:
            all_variable_location_list.append((0, 0))
    # #free_some_mem_by_gc()

def process_inlined_subroutine(all_variable_location_list, subroutine, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction, ebp_offset_list,esp_offset_list,indent_level):
    """Process an inlined subroutine."""
    for child in subroutine.iter_children():
        if child.tag == "DW_TAG_lexical_block":
            process_lexical_block(all_variable_location_list, child, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name, ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list,indent_level)
        elif child.tag == 'DW_TAG_variable':
            process_variable(all_variable_location_list, child, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name,ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list, indent_level)
            # process_variable(all_variable_location_list,child, location_lists, loc_parser, dwarfinfo, CU, indent_level)
            # process_variable(all_variable_location_list,child, data_region_tuple, rodata_range_tuple, bss_range_tuple, location_lists, loc_parser, dwarfinfo, CU, arch, json_db, binary_name, cu_name, indent_level)

def check_range_return_region(input_tuple, data_region_tuple, rodata_range_tuple, bss_range_tuple):
    first = input_tuple[0]
    second = input_tuple[1]
        # Check if the element belongs to the data region
    if data_region_tuple[0] <= first <= data_region_tuple[1] and data_region_tuple[0] <= second <= data_region_tuple[1]:
        print(f"{input_tuple} belongs to the data region.")
        return 0
    # Check if the element belongs to the rodata region
    elif rodata_range_tuple[0] <= first <= rodata_range_tuple[1] and rodata_range_tuple[0] <= second <= rodata_range_tuple[1]:
        print(f"{input_tuple} belongs to the rodata region.")
        return 1
    # Check if the element belongs to the bss region
    elif bss_range_tuple[0] <= first <= bss_range_tuple[1] and bss_range_tuple[0] <= second <= bss_range_tuple[1]:
        print(f"{input_tuple} belongs to the bss region.")
        return 2
    else:
        print(f"{input_tuple} does not belong to any known region.")
        return None

def check_concrete_addr_return_region(input_num, gt_global_data):
    # first = input_tuple[0]
    # second = input_tuple[1]
        # Check if the element belongs to the data region
    for itm in range(len(gt_global_data)):
        if gt_global_data[itm]['start_angr'] <= input_num <= gt_global_data[itm]['end_angr']:
        # print(f"{input_tuple} belongs to the data region.")
            return itm, (input_num - gt_global_data[itm]['start_angr'])
    # #free_some_mem_by_gc()
    return None, None

def return_global_start_address(gt_global_data):
    global_start_addr = {}
    for itm in gt_global_data:
        global_start_addr[itm['region']] = itm['start']
    return global_start_addr

    
def process_global_region(csv_path,data_region_tuple,rodata_range_tuple, bss_range_tuple,die, location_lists, loc_parser,dwarfinfo,CU, arch,json_db, binary_name, cu_name, indent_level='    '):
    """ A recursive function for showing information about a function DIE and its
        variables.
    """
    all_variable_dwarf_list = []
    if die.tag == 'DW_TAG_variable':

        variable_name = die.attributes.get('DW_AT_name', None)
        flag_declare = False
        declaration = die.attributes.get('DW_AT_declaration', None)
        if declaration is not None:
            flag_declare = True
        if variable_name is not None and flag_declare ==False:
            print(indent_level + '    Variable: %s' % variable_name.value)
            var_size = process_variable_location(die, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
            #need a new function for global region 
            list_lower_upper_var = process_variable_dwarf_loc_global_region(data_region_tuple,rodata_range_tuple,die, location_lists, loc_parser, dwarfinfo, CU, arch, var_size, indent_level + '      ')
            print(list_lower_upper_var)
            l = give_var_location_str(die, location_lists, loc_parser, dwarfinfo, CU, indent_level + '      ')
            result = ''
            for element in l:
                result += element + ' '

            # # Remove the trailing space
            result = result.rstrip()
            all_variable_dwarf_list.append(result)
            try:
                if list_lower_upper_var is not None:
                    # if len(list_lower_upper_var)>= 1:
                    #     append_to_csv(csv_path, [list_lower_upper_var[0][0], list_lower_upper_var[0][1], var_size,result])
                    # else:
                    #     append_to_csv(csv_path, [var_size,result])
                
                    if len(list_lower_upper_var)>= 1:
                        #now you have the address ranges of each varaible: -> now chekc where does it belong -> then append in the json 
                        #check the region & update the list accordingly
                        region = check_range_return_region(list_lower_upper_var[0],data_region_tuple, rodata_range_tuple, bss_range_tuple)
                        if region is not None:
                            #calculaet the offset first
                            start = json_db[region]['start']
                            end = json_db[region]['end']
                            end_off = end-start
                            tuple_cur = list_lower_upper_var[0]
                            start_off = tuple_cur[0]-start
                            end_cur_off = tuple_cur[1]-start
                            if json_db[region]['offsets'] is None:
                                json_db[region]['offsets'] = [0,start_off, end_cur_off,end_off]
                            else:
                                #before saving it, do a set to remove duplicate
                                json_db[region]['offsets'].append(start_off)
                                json_db[region]['offsets'].append(end_cur_off)

            except Exception as e:
                append_to_csv(csv_error_collect, [str(e)])
                # #free_some_mem_by_gc()
                print_red(e)    
    child_indent = indent_level + '  '
    for child in die.iter_children():
        if child.tag == 'DW_TAG_variable':
            process_global_region(csv_path,data_region_tuple,rodata_range_tuple, bss_range_tuple,child,  location_lists, loc_parser, dwarfinfo, CU, arch,json_db,binary_name, cu_name, child_indent)

def process_variable_dwarf_loc_global_region(data_region_tuple,rodata_range_tuple,die, location_lists, loc_parser, dwarfinfo, CU, arch, var_size, indent_level='    '):
    print("location class")
    dwarf_str_loc = []
    loc = die.attributes.get("DW_AT_location")
    if loc is not None:
        print(loc)
    else:
        print('not found')
    for attr in die.attributes.values():
                    
        if loc_parser.attribute_has_location(attr, CU['version']):
            # print('   DIE %s. attr %s.' % (die.tag, attr.name))
            loc = loc_parser.parse_from_attribute(attr,
                                                    CU['version'], die)
            # We either get a list (in case the attribute is a
            # reference to the .debug_loc section) or a LocationExpr
            # object (in case the attribute itself contains location
            # information).
            if isinstance(loc, LocationExpr):
                # pass
                if arch == 'x64':
                    list_ret = []
                    print('%s' % ( describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)))
                    single_location = str(describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                    # dwarf_str_loc.append(single_location)
                    single_location_new = remove_chars(single_location, "( )")
                    try: 
                        if 'DW_OP_addr' in single_location_new:
                            offset = single_location_new.split(':')
                            if len(offset) > 1:
                                # if 'Ox' in offset[0:2]:
                                lower = int('0x'+offset[1].strip(),16)
                                # else:
                                #     lower = int(offset[1].strip())
                                upper = lower + var_size
                                list_ret.append((lower, upper))
                    except Exception as e:
                        append_to_csv(csv_error_collect, [str(e)])
                        # #free_some_mem_by_gc()
                        print(e)
                    return list_ret
                elif arch == 'x86':
                    list_ret = []
                    print('%s' % ( describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)))
                    single_location = str(describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                    single_location_new = remove_chars(single_location, "( )")
                    try: 
                        if 'DW_OP_addr' in single_location_new:
                            offset = single_location_new.split(':')
                            if len(offset) > 1:
                                lower = int('0x'+offset[1].strip(),16)
                                upper = lower + var_size
                                list_ret.append((lower, upper))
                    except Exception as e:
                        append_to_csv(csv_error_collect, [str(e)])
                        # #free_some_mem_by_gc()
                        print(e)
                    return list_ret

            elif isinstance(loc, list):
                print_red("loc list exists")
                # ##pdb.set_trace()
                # if arch == 'x64':
                #     list_ret_val = []
                #     print(show_loclist(loc, dwarfinfo, '      ', CU.cu_offset))
                #     for loc_entity in loc:
                #         if isinstance(loc_entity, LocationEntry):
                #             # pass
                #             composite_loc_desciptor = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                #             if 'DW_OP_stack_value' in composite_loc_desciptor or \
                #                 'DW_OP_deref' in composite_loc_desciptor:
                #                 pass
                #             elif 'DW_OP_piece:' in composite_loc_desciptor:
                #                 composite_loc_desciptor_list = composite_loc_desciptor.split(';')
                #                 for i, itm in enumerate(composite_loc_desciptor_list[:-1]):
                #                     next_item = composite_loc_desciptor_list[i+1]
                #                     print(next_item)
                #                     next_item = remove_chars(next_item, "( )")
                #                     try: 
                #                         if 'DW_OP_fbreg' in itm:
                #                             bytes = next_item.split(':')[1]
                #                             offset = itm.split(':')
                #                             if len(offset) > 1: 
                #                                 lower = int(offset[1].strip()) + 16
                #                                 upper = lower + int(bytes.strip())
                #                                 list_ret_val.append((lower, upper))
                #                             #add ot to the list
                #                         elif "rbp" in itm:
                #                             bytes = next_item.split(':')[1]
                #                             offset = itm.split(':')
                #                             if len(offset) > 1:
                #                                 lower = int(offset[1].strip())
                #                                 upper = lower + int(bytes.strip())
                #                                 list_ret_val.append((lower, upper))
                #                             else:
                #                                 lower = 0
                #                                 upper = lower + int(bytes.strip())
                #                                 list_ret_val.append((lower, upper))
                #                     except Exception as e:
                #                         print(e)
                #             elif 'DW_OP_fbreg' in composite_loc_desciptor:
                #                 try:
                #                     composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                #                     offset = composite_loc_desciptor_new.split(':')
                #                     if len(offset) > 1:
                #                         lower = int(offset[1].strip()) + 16
                #                         upper = lower + var_size
                #                         list_ret_val.append((lower, upper))
                #                 except Exception as e:
                #                         print(e)
                #             elif 'ebp' in composite_loc_desciptor:
                #                 try:
                #                     composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                #                     offset = composite_loc_desciptor_new.split(':')
                #                     if len(offset) > 1:
                #                         lower = int(offset[1].strip())
                #                         upper = lower + var_size
                #                         list_ret_val.append((lower, upper))
                #                     else:
                #                         lower = 0
                #                         upper = lower + var_size
                #                         list_ret_val.append((lower, upper))
                #                 except Exception as e:
                #                         print(e)
                #     #process the loclist values a bit here
                #     list_ret_val = list(OrderedDict.fromkeys(list_ret_val))
                #     list_ret_val = merge_overlapping_tuples(list_ret_val)
                #     print('proccessed interval ---->', list_ret_val)
                #     return list_ret_val
                # if arch == 'x86':
                #     list_ret_val = []
                #     print(show_loclist(loc, dwarfinfo, '      ', CU.cu_offset))
                #     for loc_entity in loc:
                #         if isinstance(loc_entity, LocationEntry):
                #             # pass
                #             composite_loc_desciptor = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                #             if 'DW_OP_stack_value' in composite_loc_desciptor or \
                #                 'DW_OP_deref' in composite_loc_desciptor:
                #                 pass
                #             elif 'DW_OP_piece:' in composite_loc_desciptor:
                #                 composite_loc_desciptor_list = composite_loc_desciptor.split(';')
                #                 for i, itm in enumerate(composite_loc_desciptor_list[:-1]):
                #                     next_item = composite_loc_desciptor_list[i+1]
                #                     print(next_item)
                #                     next_item = remove_chars(next_item, "( )")
                #                     try: 
                #                         if 'DW_OP_fbreg' in itm:
                #                             bytes = next_item.split(':')[1]
                #                             offset = itm.split(':')
                #                             if len(offset) > 1: 
                #                                 lower = int(offset[1].strip()) + 16
                #                                 upper = lower + int(bytes.strip())
                #                                 list_ret_val.append((lower, upper))
                #                             #add ot to the list
                #                         elif "ebp" in itm:
                #                             bytes = next_item.split(':')[1]
                #                             offset = itm.split(':')
                #                             if len(offset) > 1:
                #                                 lower = int(offset[1].strip())
                #                                 upper = lower + int(bytes.strip())
                #                                 list_ret_val.append((lower, upper))
                #                             else:
                #                                 lower = 0
                #                                 upper = lower + int(bytes.strip())
                #                                 list_ret_val.append((lower, upper))
                #                     except Exception as e:
                #                         print(e)
                #             elif 'DW_OP_fbreg' in composite_loc_desciptor:
                #                 try:
                #                     composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                #                     offset = composite_loc_desciptor_new.split(':')
                #                     if len(offset) > 1:
                #                         lower = int(offset[1].strip()) + 8
                #                         upper = lower + var_size
                #                         list_ret_val.append((lower, upper))
                #                 except Exception as e:
                #                         print(e)
                #             elif 'ebp' in composite_loc_desciptor:
                #                 try:
                #                     composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                #                     offset = composite_loc_desciptor_new.split(':')
                #                     if len(offset) > 1:
                #                         lower = int(offset[1].strip())
                #                         upper = lower + var_size
                #                         list_ret_val.append((lower, upper))
                #                     else:
                #                         lower = 0
                #                         upper = lower + var_size
                #                         list_ret_val.append((lower, upper))
                #                 except Exception as e:
                #                         print(e)
                #     #process the loclist values a bit here
                #     list_ret_val = list(OrderedDict.fromkeys(list_ret_val))
                #     list_ret_val = merge_overlapping_tuples(list_ret_val)
                #     print('proccessed interval ---->', list_ret_val)
                #     return list_ret_val
                
def process_variable_location(die, location_lists, loc_parser, dwarfinfo, CU,size_list, indent_level='    '):
    # variable_name_attr = die.attributes.get('DW_AT_name')
    type_attr = die.attributes.get('DW_AT_type')
    if type_attr and die.tag != "DW_TAG_pointer_type":
        # The variable has a type attribute, which is a reference to another DIE
        try:
            type_die = CU.get_DIE_from_refaddr(type_attr.value+CU.cu_offset)
            # Further processing if the line above is successful
        except Exception as e:
            # #free_some_mem_by_gc()
            # Handle the exception
            append_to_csv(csv_error_collect, [str(e)])
            print(f"An error occurred: {e}")
            type_die = None
    # Optionally, you can include additional code to handle the exception, such as logging or raising a custom exception.
        if type_die:
            variable_type = type_die.tag
            # print(type(variable_type))
            # ##pdb.set_trace()
            
            #here seggregate whether doing it for the array or something else
            if variable_type == "DW_TAG_array_type":
                print(indent_level + '      Type arr: %s' % variable_type)
                #identify the subrange tyoes
                size_list = []
                try: 
                    for child_die in type_die.iter_children():
                        # print('=====>',child_die)
                        if 'DW_TAG_subrange_type' in child_die.tag:
                            # print("Subrange Type Found!")
                            # Process the subrange type here
                            size = process_subrange_type(child_die)
                            size_list.append(size)
                        else:
                            print("Other child found, not a subrange type.")
                except Exception as e:
                    # #free_some_mem_by_gc()
                    # Handle the exception
                    append_to_csv(csv_error_collect, [str(e), 'An error occurred while getting childern of array type'])
                    print(f"An error occurred while getting childern of array type: {e}")
                # print("size: ", size_list)
                # Recursively process the nested type and get the type information
                nested_type_info = process_variable_location(type_die, location_lists, loc_parser, dwarfinfo, CU,size_list, indent_level + '      ')
                return nested_type_info
            else:
                # size_list = []
                # print(size_list)
                if len(size_list) == 0 or type(size_list) is str:
                    size_list = []
                print(indent_level + '      Type 1: %s' % variable_type)
                # Recursively process the nested type and get the type information
                nested_type_info = process_variable_location(type_die, location_lists, loc_parser, dwarfinfo, CU,size_list, indent_level + '      ')
                return nested_type_info
        else:
             if die.attributes.get('DW_AT_name') is not None:
    
                print(indent_level + '    Type: %s (Type not found)' % str(die.attributes.get('DW_AT_name').value))
    else:
        if die.attributes.get('DW_AT_name') is not None:
            print(indent_level + '    Type: %s (No type information)' % str(die.attributes.get('DW_AT_name').value))

    # If there is no more recursion, print a message and return some indication
    #reached the end of the nesting -> its time to return the size
    #get current element size:
    curr_size_byte = die.attributes.get('DW_AT_byte_size')
    curr_size_bit = die.attributes.get('DW_AT_bit_size')
    cur_size_individual = 0
    if curr_size_byte is None:
        if curr_size_bit is None:
            cur_size_individual = 0
        else:
            cur_size_individual = ((curr_size_bit).value/8)
    else:
        cur_size_individual = curr_size_byte.value

    #multiply each element of the size array
    mul = 1
    final_size = 0
    if len(size_list) > 0 and type(size_list) is list:
        for i in size_list:
            mul = mul * i
        final_size = mul * cur_size_individual
    else:
        final_size = cur_size_individual
    if die.attributes.get('DW_AT_name') is not None:
        print(indent_level + '  No more nested types at this level, name:', die.attributes.get('DW_AT_name').value )
    print(indent_level + '  No more nested types at this level, size in bytes:', final_size )
    return final_size

# now will be returning two extra thing:  #ebp_offset_list and  #esp_offset_list, alogn with whatever it was returning
def process_variable_dwarf_loc(die, location_lists, loc_parser, dwarfinfo, CU, arch, var_size, ebp_presence,extra_offset_subtraction,ebp_offset_list,esp_offset_list,indent_level='    '):
    print("location class")
    dwarf_str_loc = []
    loc = die.attributes.get("DW_AT_location")
    if loc is not None:
        print(loc)
    else:
        print('not found')
    for attr in die.attributes.values():
                    
        if loc_parser.attribute_has_location(attr, CU['version']):
            # print('   DIE %s. attr %s.' % (die.tag, attr.name))
            loc = loc_parser.parse_from_attribute(attr,
                                                    CU['version'], die)
            # We either get a list (in case the attribute is a
            # reference to the .debug_loc section) or a LocationExpr
            # object (in case the attribute itself contains location
            # information).
            if isinstance(loc, LocationExpr):
                # pass -> changes are nto doen for x64 architecture, change it later following the x86
                if arch == 'x64':
                    list_ret = []
                    print('%s' % ( describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)))
                    single_location = str(describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                    # dwarf_str_loc.append(single_location)
                    single_location_new = remove_chars(single_location, "( )")
                    try: 
                        if 'DW_OP_stack_value' in single_location_new or \
                                    'DW_OP_deref' in single_location_new:
                                    pass
                        elif 'DW_OP_fbreg' in single_location_new:
                            offset = single_location_new.split(':')
                            if len(offset) > 1:
                                lower = int(offset[1].strip()) + 16
                                upper = lower + var_size
                                list_ret.append((lower, upper))
                        elif 'rbp' in single_location_new:
                            offset = single_location_new.split(':')
                            if len(offset) > 1:
                                lower = int(offset[1].strip())
                                upper = lower + var_size
                                list_ret.append((lower, upper))
                            else:
                                lower = 0
                                upper = lower + var_size
                                list_ret.append((lower, upper))
                    except Exception as e:
                        append_to_csv(csv_error_collect, [str(e)])
                        #free_some_mem_by_gc()
                        print(e)
                    return list_ret
                elif arch == 'x86':
                    list_ret = []
                    print('%s' % ( describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)))
                    single_location = str(describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                    single_location_new = remove_chars(single_location, "( )")
                    try: 
                        if 'DW_OP_stack_value' in single_location_new or \
                                    'DW_OP_deref' in single_location_new:
                                    pass
                        elif 'DW_OP_fbreg' in single_location_new:
                            offset = single_location_new.split(':')
                            if len(offset) > 1:
                                #if fbreg then always + 4 to adjust the 4 bute return address 
                                lower = int(offset[1].strip()) + 4
                                upper = lower + var_size
                                list_ret.append((lower, upper))
                        elif 'ebp' in single_location_new:
                            offset = single_location_new.split(':')
                            if len(offset) > 1:
                                lower = int(offset[1].strip())
                                if lower not in ebp_offset_list:
                                    ebp_offset_list.append(lower)
                                if lower+var_size not in ebp_offset_list:
                                        ebp_offset_list.append(lower+var_size)
                                if ebp_presence:
                                    #this is starting from the CFA i.e. just after the ret_address push, 4 byte for initial push rbp, extra 4 byte for any other push
                                    lower = lower - extra_offset_subtraction
                                    upper = lower + var_size
                                    list_ret.append((lower, upper))
                            else:
                                lower = 0
                                if lower not in ebp_offset_list:
                                    ebp_offset_list.append(lower)
                                if lower+var_size not in ebp_offset_list:
                                        ebp_offset_list.append(lower+var_size)
                                if ebp_presence:
                                    #this is starting from the CFA i.e. just after the ret_address push, 4 byte for initial push rbp, extra 4 byte for any other push
                                    lower = lower - extra_offset_subtraction
                                    upper = lower + var_size                                    
                                    list_ret.append((lower, upper))
                        elif 'esp' in single_location_new:
                            offset = single_location_new.split(':')
                            if len(offset) > 1:
                                lower = int(offset[1].strip())
                                if lower not in esp_offset_list:
                                    esp_offset_list.append(lower)
                                upper = lower + var_size
                                if upper not in esp_offset_list:
                                    esp_offset_list.append(upper)
                                # list_ret.append((lower, upper))
                            else:
                                lower = 0
                                if lower not in esp_offset_list:
                                    esp_offset_list.append(lower)
                                upper = lower + var_size
                                if upper not in esp_offset_list:
                                    esp_offset_list.append(upper)
                                # list_ret.append((lower, upper))
                    except Exception as e:
                        append_to_csv(csv_error_collect, [str(e)])
                        #free_some_mem_by_gc()
                        print(e)
                    return list_ret

            elif isinstance(loc, list):
                # ##pdb.set_trace()
                # pass -> changes are nto doen for x64 architecture, change it later following the x86
                if arch == 'x64':
                    list_ret_val = []
                    print(show_loclist(loc, dwarfinfo, '      ', CU.cu_offset))
                    for loc_entity in loc:
                        if isinstance(loc_entity, LocationEntry):
                            # pass
                            composite_loc_desciptor = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                            if 'DW_OP_stack_value' in composite_loc_desciptor or \
                                'DW_OP_deref' in composite_loc_desciptor:
                                pass
                            elif 'DW_OP_piece:' in composite_loc_desciptor:
                                composite_loc_desciptor_list = composite_loc_desciptor.split(';')
                                for i, itm in enumerate(composite_loc_desciptor_list[:-1]):
                                    next_item = composite_loc_desciptor_list[i+1]
                                    print(next_item)
                                    next_item = remove_chars(next_item, "( )")
                                    try: 
                                        if 'DW_OP_fbreg' in itm:
                                            bytes = next_item.split(':')[1]
                                            offset = itm.split(':')
                                            if len(offset) > 1: 
                                                lower = int(offset[1].strip()) + 16
                                                upper = lower + int(bytes.strip())
                                                list_ret_val.append((lower, upper))
                                            #add ot to the list
                                        elif "rbp" in itm:
                                            bytes = next_item.split(':')[1]
                                            offset = itm.split(':')
                                            if len(offset) > 1:
                                                lower = int(offset[1].strip())
                                                upper = lower + int(bytes.strip())
                                                list_ret_val.append((lower, upper))
                                            else:
                                                lower = 0
                                                upper = lower + int(bytes.strip())
                                                list_ret_val.append((lower, upper))
                                    except Exception as e:
                                        append_to_csv(csv_error_collect, [str(e)])
                                        #free_some_mem_by_gc()
                                        print(e)
                            elif 'DW_OP_fbreg' in composite_loc_desciptor:
                                try:
                                    composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                                    offset = composite_loc_desciptor_new.split(':')
                                    if len(offset) > 1:
                                        lower = int(offset[1].strip()) + 16
                                        upper = lower + var_size
                                        list_ret_val.append((lower, upper))
                                except Exception as e:
                                        append_to_csv(csv_error_collect, [str(e)])
                                        #free_some_mem_by_gc()
                                        print(e)
                            elif 'ebp' in composite_loc_desciptor:
                                try:
                                    composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                                    offset = composite_loc_desciptor_new.split(':')
                                    if len(offset) > 1:
                                        lower = int(offset[1].strip())
                                        upper = lower + var_size
                                        list_ret_val.append((lower, upper))
                                    else:
                                        lower = 0
                                        upper = lower + var_size
                                        list_ret_val.append((lower, upper))
                                except Exception as e:
                                        append_to_csv(csv_error_collect, [str(e)])
                                        #free_some_mem_by_gc()
                                        print(e)
                    #process the loclist values a bit here
                    list_ret_val = list(OrderedDict.fromkeys(list_ret_val))
                    list_ret_val = merge_overlapping_tuples(list_ret_val)
                    print('proccessed interval ---->', list_ret_val)
                    return list_ret_val
                if arch == 'x86':
                    list_ret_val = []
                    print(show_loclist(loc, dwarfinfo, '      ', CU.cu_offset))
                    for loc_entity in loc:
                        if isinstance(loc_entity, LocationEntry):
                            # pass
                            composite_loc_desciptor = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                            if 'DW_OP_stack_value' in composite_loc_desciptor or \
                                'DW_OP_deref' in composite_loc_desciptor:
                                pass
                            elif 'DW_OP_piece:' in composite_loc_desciptor:
                                composite_loc_desciptor_list = composite_loc_desciptor.split(';')
                                for i, itm in enumerate(composite_loc_desciptor_list[:-1]):
                                    next_item = composite_loc_desciptor_list[i+1]
                                    print(next_item)
                                    next_item = remove_chars(next_item, "( )")
                                    try: 
                                        if 'DW_OP_fbreg' in itm:
                                            bytes = next_item.split(':')[1]
                                            offset = itm.split(':')
                                            if len(offset) > 1: 
                                                lower = int(offset[1].strip()) + 4
                                                upper = lower + int(bytes.strip())
                                                list_ret_val.append((lower, upper))
                                            #add ot to the list
                                        elif "ebp" in itm:
                                            bytes = next_item.split(':')[1]
                                            offset = itm.split(':')
                                            if len(offset) > 1:
                                                lower = int(offset[1].strip())
                                                if lower not in ebp_offset_list:
                                                    ebp_offset_list.append(lower)
                                                if lower+int(bytes.strip()) not in ebp_offset_list:
                                                        ebp_offset_list.append(lower+int(bytes.strip()))
                                                if ebp_presence:
                                                    #this is starting from the CFA i.e. just after the ret_address push, 4 byte for initial push rbp, extra 4 byte for any other push
                                                    lower = lower - extra_offset_subtraction
                                                    upper = lower + int(bytes.strip())                                                    
                                                    list_ret_val.append((lower, upper))
                                            else:
                                                lower = 0
                                                if lower not in ebp_offset_list:
                                                    ebp_offset_list.append(lower)
                                                if lower+int(bytes.strip()) not in ebp_offset_list:
                                                        ebp_offset_list.append(lower+int(bytes.strip()))
                                                if ebp_presence:
                                                    #this is starting from the CFA i.e. just after the ret_address push, 4 byte for initial push rbp, extra 4 byte for any other push
                                                    lower = lower - extra_offset_subtraction
                                                    upper = lower + int(bytes.strip())                                                   
                                                    list_ret_val.append((lower, upper))
                                        elif "esp" in itm:
                                            bytes = next_item.split(':')[1]
                                            offset = itm.split(':')
                                            if len(offset) > 1:
                                                lower = int(offset[1].strip())
                                                if lower not in esp_offset_list:
                                                    esp_offset_list.append(lower)
                                                upper = lower + int(bytes.strip())
                                                if upper not in esp_offset_list:
                                                    esp_offset_list.append(upper)
                                                # list_ret_val.append((lower, upper))
                                            else:
                                                lower = 0
                                                if lower not in esp_offset_list:
                                                    esp_offset_list.append(lower)
                                                upper = lower + int(bytes.strip())
                                                if upper not in esp_offset_list:
                                                    esp_offset_list.append(upper)
                                                # list_ret_val.append((lower, upper))
                                    except Exception as e:
                                        append_to_csv(csv_error_collect, [str(e)])
                                        #free_some_mem_by_gc()
                                        print(e)
                            elif 'DW_OP_fbreg' in composite_loc_desciptor:
                                try:
                                    composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                                    offset = composite_loc_desciptor_new.split(':')
                                    if len(offset) > 1:
                                #if fbreg then always + 4 to adjust the 4 bute return address 
                                        lower = int(offset[1].strip()) + 4
                                        upper = lower + var_size
                                        list_ret_val.append((lower, upper))
                                except Exception as e:
                                        append_to_csv(csv_error_collect, [str(e)])
                                        #free_some_mem_by_gc()
                                        print(e)
                            elif 'ebp' in composite_loc_desciptor:
                                try:
                                    composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                                    offset = composite_loc_desciptor_new.split(':')
                                    if len(offset) > 1:
                                        lower = int(offset[1].strip())
                                        if lower not in ebp_offset_list:
                                            ebp_offset_list.append(lower)
                                        if lower+var_size not in ebp_offset_list:
                                                ebp_offset_list.append(lower+var_size)
                                        if ebp_presence:
                                        #this is starting from the CFA i.e. just after the ret_address push, 4 byte for initial push rbp, extra 4 byte for any other push
                                            lower = lower - extra_offset_subtraction
                                            upper = lower + var_size                                            
                                            list_ret_val.append((lower, upper))
                                    else:
                                        lower = 0
                                        if lower not in ebp_offset_list:
                                            ebp_offset_list.append(lower)
                                        if lower+var_size not in ebp_offset_list:
                                                ebp_offset_list.append(lower+var_size)
                                        if ebp_presence:
                                        #this is starting from the CFA i.e. just after the ret_address push, 4 byte for initial push rbp, extra 4 byte for any other push
                                            lower = lower - extra_offset_subtraction
                                            upper = lower + var_size
                                            list_ret_val.append((lower, upper))
                                except Exception as e:
                                        append_to_csv(csv_error_collect, [str(e)])
                                        #free_some_mem_by_gc()
                                        print(e)
                            elif 'esp' in composite_loc_desciptor:
                                try:
                                    composite_loc_desciptor_new = remove_chars(composite_loc_desciptor, "( )")
                                    offset = composite_loc_desciptor_new.split(':')
                                    if len(offset) > 1:
                                        lower = int(offset[1].strip())
                                        if lower not in esp_offset_list:
                                            esp_offset_list.append(lower)
                                        upper = lower + var_size
                                        if upper not in esp_offset_list:
                                            esp_offset_list.append(upper)
                                        # list_ret_val.append((lower, upper))
                                    else:
                                        lower = 0
                                        if lower not in esp_offset_list:
                                            esp_offset_list.append(lower)
                                        upper = lower + var_size
                                        if upper not in esp_offset_list:
                                            esp_offset_list.append(upper)
                                        # list_ret_val.append((lower, upper))
                                except Exception as e:
                                        append_to_csv(csv_error_collect, [str(e)])
                                        #free_some_mem_by_gc()
                                        print(e)
                    #process the loclist values a bit here
                    list_ret_val = list(OrderedDict.fromkeys(list_ret_val))
                    list_ret_val = merge_overlapping_tuples(list_ret_val)
                    print('proccessed interval ---->', list_ret_val)
                    return list_ret_val

def get_global_regions_angr_style(project):
    # project = angr.Project(elf_file)
    data_range = None
    rodata_range = None
    bss_range = None

    # Iterate over sections
    for section in project.loader.main_object.sections:
        if section.name == '.data':
            data_range = (section.min_addr, section.max_addr)
        elif section.name == '.rodata':
            rodata_range = (section.min_addr, section.max_addr)
        elif section.name == '.bss':
            bss_range = (section.min_addr, section.max_addr)
    #free_some_mem_by_gc()
    return data_range, rodata_range, bss_range  

def remove_chars(input_string, chars_to_remove):
    result_string = ''.join(char for char in input_string if char not in chars_to_remove)
    return result_string
    
def show_loclist(loclist, dwarfinfo, indent, cu_offset):
    """ Display a location list nicely, decoding the DWARF expressions
        contained within.
    """
    d = []
    for loc_entity in loclist:
        if isinstance(loc_entity, LocationEntry):
            # pass
            d.append('%s <<%s>>' % (
                loc_entity,
                describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)))
        else:
            d.append(str(loc_entity))
    return '\n'.join(indent + s for s in d)

def show_loclist_ret_str(loclist, dwarfinfo, indent, cu_offset):
    """ Display a location list nicely, decoding the DWARF expressions
        contained within.
    """
    d = []
    for loc_entity in loclist:
        if isinstance(loc_entity, LocationEntry):
            # pass
            d.append(str(describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)))
        else:
            d.append(str(loc_entity))
    return d

def give_var_location_str(die, location_lists, loc_parser, dwarfinfo, CU, indent_level='    '):
    str_list = []
    for attr in die.attributes.values():
                    
        if loc_parser.attribute_has_location(attr, CU['version']):
            # print('   DIE %s. attr %s.' % (die.tag, attr.name))
            loc = loc_parser.parse_from_attribute(attr,
                                                    CU['version'], die)
            # We either get a list (in case the attribute is a
            # reference to the .debug_loc section) or a LocationExpr
            # object (in case the attribute itself contains location
            # information).
            if isinstance(loc, LocationExpr):
                str_list.append(str(describe_DWARF_expr(loc.loc_expr,dwarfinfo.structs, CU.cu_offset)))
                # break
            elif isinstance(loc, list):

                for itm in show_loclist_ret_str(loc, dwarfinfo, '      ', CU.cu_offset):
                # ##pdb.set_trace()
                    str_list.append(itm)
    # #free_some_mem_by_gc()
    return str_list
                # break

def remove_duplicates_and_sort(input_list):
    # Convert the list to a set to remove duplicates
    unique_elements = set(input_list)
    # Convert the set back to a list and sort it
    sorted_list = sorted(list(unique_elements))
    #free_some_mem_by_gc()
    return sorted_list

def process_subrange_type(die):
    # Add your logic to process subrange type here
    upper_bound = die.attributes.get('DW_AT_upper_bound')
    if upper_bound is None:
        upper_bound = 0
    else:
        upper_bound = upper_bound.value
    lower_bound = die.attributes.get('DW_AT_lower_bound')
    if lower_bound is None:
        lower_bound = 0
    else:
        lower_bound = lower_bound.value
    #free_some_mem_by_gc()
    return ((upper_bound-lower_bound)+1)

def merge_overlapping_tuples(tuple_list):
    # Sort the list based on the first element of each tuple
    sorted_list = sorted(tuple_list, key=lambda x: x[0])

    i = 0
    while i < len(sorted_list) - 1:
        current_tuple = sorted_list[i]
        next_tuple = sorted_list[i + 1]

        # Check for intersection and merge if needed
        if current_tuple[1] >= next_tuple[0]:
            merged_tuple = (current_tuple[0], max(current_tuple[1], next_tuple[1]))
            sorted_list[i:i + 2] = [merged_tuple]
        else:
            i += 1
    #free_some_mem_by_gc()
    return sorted_list

def flaten_sort_list(tuple_list):
    # Flatten the list of tuples
    flat_list = [item for sublist in tuple_list for item in sublist]
    flat_list.append(0)
    # Remove duplicates
    unique_list = list(set(flat_list))
    # Sort in decreasing order
    sorted_list = sorted(unique_list, reverse=True)
    #free_some_mem_by_gc()
    return sorted_list

def given_file_name_return_json_file_name(proj,binary_path, json_file_path,global_json_file_path):
    '''
    The coding logic for the integration is as follows: 
        1. First generate the GT data  => save it wisth the filename
        2. Then read the filename while 
    '''
    try:
        if is_elf(binary_path):
            print(f"Processing binary: {binary_path}")
            json_db = []  # Create an empty list for each binary file
            jsob_db_global_region = []
            #TODO: just a temporary patch, we need to mark it down later
            data_range, rodata_range, bss_range = get_global_regions_angr_style(proj)
            jsob_db_global_region.append({
                'filename': os.path.basename(binary_path),
                'region' : '.data',
                'start': None,
                'end' : None,
                'offsets' : None,
                'codeaddr': None,
                'start_angr': data_range[0],
                'end_angr' : data_range[1]
            })
            jsob_db_global_region.append({
                'filename': os.path.basename(binary_path),
                'region' : '.rodata',
                'start': None,
                'end' : None,
                'offsets' : None,
                'codeaddr': None,
                'start_angr':rodata_range[0],
                'end_angr' : rodata_range[1]
            })
            jsob_db_global_region.append({
                'filename': os.path.basename(binary_path),
                'region' : '.bss',
                'start': None,
                'end' : None,
                'offsets' : None,
                'codeaddr': None,
                'start_angr': bss_range[0],
                'end_angr' : bss_range[1]
            })
            process_file(binary_path, json_db, jsob_db_global_region)
            #process the global region data: make a set to remove duplicate followied by sort
            for itm in jsob_db_global_region:
                if itm['offsets'] is not None:
                    itm['offsets'] = remove_duplicates_and_sort( itm['offsets'])
            # global_json_file_path = '/'.join(json_file_path.split('/')[0:-1])+"global_"+json_file_path.split('/')[1]
            with open(json_file_path, 'w') as json_file:
                json.dump(json_db, json_file, indent=4)
                # json_file.write('\n')  # Add a newline for better readability between entries
            with open(global_json_file_path, 'w') as json_file2:
                json.dump(jsob_db_global_region, json_file2, indent=4)
            # #free_some_mem_by_gc()
            return json_file_path

    except Exception as e:
        print(f"An error occurred: {e}")
        append_to_csv(csv_error_collect, [str(e)])
        traceback_info = traceback.format_exc()
        print("Traceback:")
        print(traceback_info)
        #free_some_mem_by_gc()
        return None

def create_folder_if_not_exists(folder_path):
    """
    Check if the folder exists, if not, create it.

    Args:
    - folder_path (str): The path to the folder to be checked/created.
    """
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_path}' created successfully.")
    else:
        print(f"Folder '{folder_path}' already exists.")

def append_to_csv(csv_file_path, data, delimiter=','):
    with open(csv_file_path, mode='a', newline='') as file:
        writer = csv.writer(file, delimiter=delimiter)

        # Write the data to the file
        # for row in data:
        writer.writerow(data)

        print("Data appended to the CSV file successfully.")

##new section for global region
#+++++++++++++++++++++++++++++++++++++GT CODE ENDS ++++++++++++++++++++++++++++++++++++++++++++++

def main_start(bin_path):

    '''
    step 1: get the binary -> then generate the GT json file
    step 2: save the results to the CSV file/ json file
    '''
    #the input binary folder path
    binary_path = bin_path
    print("Processing binary: "+binary_path)
    #the output folder path for ground truth
    GT_out_folder = "./result/"
    create_folder_if_not_exists(GT_out_folder)
   
    print_green_bold('---------START-----------'+ binary_path)
    print_cyan("step 1(START): Generate the GT file and store it in")
    proj = angr.Project(binary_path,use_sim_procedures=True, load_options={'auto_load_libs': False})
    # cfg = proj.analyses.CFGFast()
    # json_file_path = GT_out_folder+binary_path.split('/')[-1]+'.json'
    # global_json_file_path = GT_out_folder+'global_'+binary_path.split('/')[-1]+'.json'

    # 确保输出目录存在
    os.makedirs("gt_out_folder", exist_ok=True)

    # 获取文件名，不含路径
    binary_name = os.path.basename(binary_path)

    # 构造跨平台路径
    global_json_file_path = os.path.join("gt_out_folder", f"global_{binary_name}.json")
    json_file_path = os.path.join("gt_out_folder", f"{binary_name}.json")
    given_file_name_return_json_file_name(proj,binary_path,json_file_path, global_json_file_path)
    print_cyan("step 1(END): "+json_file_path+" successfully stored")
   
if __name__ == '__main__':
    bin_path = sys.argv[1]
    main_start(bin_path)

#+++++++++++++++++++++++++++++++++++++Main CODE ENDS ++++++++++++++++++++++++++++++++++++++++++++++
