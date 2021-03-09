#
# Copyright 2021, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(libsel4prof C)

file(GLOB deps src/*.c)

list(SORT deps)

add_library(sel4prof STATIC EXCLUDE_FROM_ALL ${deps})
target_include_directories(sel4prof PUBLIC include)
target_link_libraries(sel4prof utils muslc sel4bench sel4runtime)

if (Sel4ProfEnableInstrumentation)
    target_compile_options(
        sel4prof
        INTERFACE
        "-finstrument-functions"
        "-fpatchable-function-entry=26,25"
    )
endif()

# Functions that should not be instrumented
set(ProfExcludeFunctions OFF CACHE INTERNAL "Enable profiling measuerments on libraries linked to sel4prof")
function(ProfExcludeFunctions target)
    foreach(symbol ${ARGN})
        target_compile_options(
            "${target}"
            PUBLIC
            "finstrument-functions-exclude-function-list=${symbol}"
        )
    endforeach()
endfunction()

# Files from which functions should not be instrumented
function(ProfExcludeFiles target)
    foreach(symbol ${ARGN})
        target_compile_options(
            "${target}"
            PUBLIC
            "finstrument-functions-exclude-function-list=${symbol}"
        )
    endforeach()
endfunction()

# Ensure CapDL makes text pages writeable so we can write profiling data
# in the text region
set(CapDLLoaderWriteablePages ON CACHE BOOL "" FORCE)
