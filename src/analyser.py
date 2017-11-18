#!/usr/bin/env python3.6

import json
import sys

from pattern import Pattern


def analysis(file):
    patterns = get_patterns("patterns")
    ast = None

    with open(file, 'r') as json_slice:
        ast = json.load(json_slice)

    for pattern in patterns:
        tainted = []
        untainted = []
        if ast['kind'] == 'program':
            for element in ast['children']:
                if element['kind'] == 'assign':
                    right = element['right']
                    if right['kind'] == 'offsetlookup':
                        visit_assign_offsetlookup(element, pattern, tainted)

                    if right['kind'] == 'call':
                        visit_assign_call(element, pattern, tainted)

                    if right['kind'] == 'encapsed':
                        visit_encapsed(element, tainted)

                    if right['kind'] == 'bin':
                        visit_bin(element, tainted)

                if element['kind'] in pattern.sensitiveSinks:
                    arguments = element['arguments']
                    for argument in arguments:
                        if argument['kind'] == 'offsetlookup':
                            visit_offsetlookup(argument, pattern, tainted)
                            # if element["kind"] == "call":

                if element['kind'] == 'call':
                    visit_call(element, pattern, tainted)

                    # if element["kind"] == "while":
                    #    visitWhile(element, pattern, tainted)


def visit_offsetlookup(argument, pattern, tainted):
    if 'what' in argument:
        what = argument['what']
        for entry in pattern.entries:
            if what['name'] == entry.strip('$'):
                print('slice is vulnerable')


def visit_assign_offsetlookup(element, pattern, tainted):
    right = element['right']
    if 'what' in right:
        what = right['what']
        if what['kind'] == 'variable':
            for entry in pattern.entries:
                if what['name'] == entry.strip('$'):
                    taint = element['left']['name']
                    if taint != '' and not taint in tainted:
                        tainted.append(taint)


def visit_assign_call(element, pattern, tainted):
    right = element['right']
    if 'what' in right:
        what = right['what']
        if what['kind'] == 'identifier':
            for sensitiveSink in pattern.sensitiveSinks:
                if what['name'] == sensitiveSink:
                    for argument in right['arguments']:
                        if argument['name'] in tainted:
                            print('slice is vulnerable')
            for sanitization in pattern.sanitizations:
                if what['name'] == sanitization:
                    for argument in right['arguments']:
                        if argument['name'] in tainted:
                            tainted.remove(argument['name'])
    return ""


def visit_call(element, pattern, tainted):
    if 'what' in element:
        what = element['what']
        for sensitiveSink in pattern.sensitiveSinks:
            if what['name'] == sensitiveSink:
                for argument in element['arguments']:
                    if 'name' in argument:
                        if argument['name'] in tainted:
                            print('slice is vulnerable')


def visit_encapsed(element, tainted):
    right = element['right']
    if 'value' in right:
        for value in right['value']:
            if 'name' in value:
                if value['name'] in tainted:
                    if not element['left']['name'] in tainted:
                        tainted.append(element['left']['name'])


def visit_bin(element, tainted):
    if 'kind' in element['left']:
        if element['left']['kind'] == 'variable':
            top_var = element['left']['name']
    else:
        return
    right = element['right']
    if right['kind'] == 'variable':
        if right['name'] in tainted:
            if top_var != '' and not top_var in tainted:
                tainted.append(top_var)
    if 'left' in right:
        visit_bin_rec(right, tainted, top_var)


def visit_bin_rec(element, tainted, top_var):
    if element['kind'] == 'variable':
        if element['name'] in tainted:
            if top_var != "" and not top_var in tainted:
                tainted.append(top_var)

    if "left" in element:
        left = element["left"]
        visit_bin_rec(left, tainted, top_var)

    if "right" in element:
        right = element["right"]
        visit_bin_rec(right, tainted, top_var)


def get_patterns(file_name):
    file = open(file_name, 'r')
    patterns = []

    while True:
        vuln_type = file.readline().strip("\n")
        if vuln_type == "":
            break
        entries = file.readline().strip("\n").split(",")
        sanitizations = file.readline().strip("\n").split(",")
        sensitiveSinks = file.readline().split(",")
        file.readline()
        patterns.append(Pattern(vuln_type, entries, sanitizations, sensitiveSinks))

    return patterns


if __name__ == '__main__':
    if sys.version_info < (3, 6):
        raise ValueError('python >= 3.6 required')

    analysis(sys.argv[1])
