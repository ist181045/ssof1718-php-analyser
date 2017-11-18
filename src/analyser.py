#!/usr/bin/env python3.6

import json
import sys
from typing import List, Union

from pattern import Pattern


def analysis(file: str) -> None:
    patterns = get_patterns('patterns')

    with open(file, 'r') as json_slice:
        ast = json.load(json_slice)

    for pattern in patterns:
        tainted = []
        vars = {}

        if ast['kind'] == 'program':
            for element in ast['children']:
                visit_element(element, pattern, tainted, vars)


def visit_element(element: dict, pattern: Pattern, tainted: list,
                  vars: dict) -> None:
    if element['kind'] == 'assign':
        left = element['left']
        right = element['right']
        if right['kind'] == 'offsetlookup':
            vars[left['name']] = visit_assign_offsetlookup(element, pattern,
                                                           tainted)

        if right['kind'] == 'call':
            visit_assign_call(element, pattern, tainted, vars)

        if right['kind'] == 'encapsed':
            vars[left['name']] = visit_encapsed(element, tainted, vars)

        if right['kind'] == 'bin':
            vars[left['name']] = visit_bin(element, tainted, vars)


        if left['kind'] == 'variable':
            if right['kind'] == 'variable':
                if right['name'] in tainted:
                    if left['name'] not in tainted:
                        tainted.append(left['name'])
                if right['name'] in vars:
                    vars[left['name']] = vars[right['name']]

            if right['kind'] == 'string':
                vars[left['name']] = right['value']

    if element['kind'] in pattern.sinks:
        arguments = element['arguments']
        for argument in arguments:
            if argument['kind'] == 'offsetlookup':
                visit_offsetlookup(argument, pattern, tainted)

    if element['kind'] == 'call':
        visit_call(element, pattern, tainted)

    if element['kind'] == 'if':
        visit_if(element, pattern, tainted, vars)

    if element['kind'] == 'while':
        visit_while(element, pattern, tainted, vars)


def visit_if(element: dict, pattern: Pattern, tainted: list, vars: dict) -> None:
    body = element['body']
    for child in body['children']:
        visit_element(child, pattern, tainted, vars)
    alternate = element['alternate']
    if alternate is not None:
        if alternate['kind'] == 'if':
            visit_if(alternate, pattern, tainted, vars)
        else:
            for child in alternate['children']:
                visit_element(child, pattern, tainted, vars)


def visit_while(element: dict, pattern: Pattern, tainted: list,
                vars: dict) -> None:
    test = element['test']
    topVar = ''
    testRight = ''
    if test['kind'] == 'bin':
        topVar = test['left']['name']
        testType = test['type']
        testRight = test['right']['value']
        topChange = False
    body = element['body']
    for children in body['children']:
        if 'left' in children:
            if children['left']['name'] == topVar:
                topChange = True


    if topChange == True and topVar in vars:
        if testType == '!=':
            visit_while_diff_test(body, pattern, tainted, vars, topVar, testRight)
        elif testType == '==':
            visit_while_equal_test(body, pattern, tainted, vars, topVar, testRight)

    elif topChange == True and topVar not in vars:
        vars[topVar] = ""
        if testType == '!=':
            visit_while_diff_test(body, pattern, tainted, vars, topVar, testRight)
        elif testType == '==':
            visit_while_equal_test(body, pattern, tainted, vars, topVar, testRight)
        vars[topVar] = "notEmpty"
        if testType == '!=':
            visit_while_diff_test(body, pattern, tainted, vars, topVar, testRight)
        elif testType == '==':
            visit_while_equal_test(body, pattern, tainted, vars, topVar, testRight)



def visit_while_diff_test(body: dict, pattern: Pattern, tainted: list,
                          vars: dict, topVar: str, testRight) -> None:
    while vars[topVar] != testRight:
        inicial = vars[topVar]
        for children in body['children']:
            visit_element(children, pattern, tainted, vars)
        if inicial == vars[topVar]:
            break

def visit_while_equal_test(body: dict, pattern: Pattern, tainted: list,
                           vars: dict, topVar: str, testRight) -> None:
    while vars[topVar] == testRight:
        inicial = vars[topVar]
        for children in body['children']:
            visit_element(children, pattern, tainted, vars)
        if inicial == vars[topVar]:
            break


def visit_offsetlookup(argument: dict, pattern: Pattern, tainted: list) -> None:
    if 'what' in argument:
        what = argument['what']
        for entry in pattern.entries:
            if what['name'] == entry.strip('$'):
                print('slice is vulnerable to ' + pattern.type)


def visit_assign_offsetlookup(element: dict, pattern: Pattern,
                              tainted: list) -> Union[dict, None]:
    right = element['right']
    if 'what' in right:
        what = right['what']
        if what['kind'] == 'variable':
            for entry in pattern.entries:
                if what['name'] == entry.strip('$'):
                    taint = element['left']['name']
                    if taint != '' and not taint in tainted:
                        tainted.append(taint)
                    return what['name']


def visit_assign_call(element: dict, pattern: Pattern, tainted: list, vars: dict) -> str:
    right = element['right']
    if 'what' in right:
        what = right['what']
        if what['kind'] == 'identifier':
            for sink in pattern.sinks:
                if what['name'] == sink:
                    for argument in right['arguments']:
                        if argument['name'] in tainted:
                            print('slice is vulnerable to ' + pattern.type)

            for sanitizer in pattern.sanitizers:
                if what['name'] == sanitizer:
                    for argument in right['arguments']:
                        if argument['name'] in tainted:
                            tainted.remove(argument['name'])

            if what['name'] == 'substr':
                if element['left']['kind'] == 'variable':
                    leftVar = element['left']['name']
                    if leftVar in vars:
                        vars[leftVar] = vars[leftVar][1:]



    return ''


def visit_call(element: dict, pattern: Pattern, tainted: list) -> None:
    if 'what' in element:
        what = element['what']
        for sink in pattern.sinks:
            if what['name'] == sink:
                for argument in element['arguments']:
                    if 'name' in argument:
                        if argument['name'] in tainted:
                            print('slice is vulnerable to ' + pattern.type)


def visit_encapsed(element: dict, tainted: list, vars: dict) -> str:
    right = element['right']
    varValue = ''
    if 'value' in right:
        for value in right['value']:
            if 'name' in value:
                if value['name'] in tainted:
                    if not element['left']['name'] in tainted:
                        tainted.append(element['left']['name'])
                if value['name'] in vars:
                    varValue += vars[value['name']]
            elif value['kind'] == 'string':
                varValue += value['value']
    return varValue


def visit_bin(element: dict, tainted: list, vars: dict) -> Union[str, None]:
    varValue = ''
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
        if right['name'] in vars:
            varValue += vars[right['name']]
    elif right['kind'] == 'string':
        varValue += right['value']
    if 'left' in right:
        varValue += visit_bin_rec(right, tainted, top_var, vars)
    return varValue


def visit_bin_rec(element: dict, tainted: list, top_var: dict,
                  vars: dict) -> str:
    varValue = ''
    if element['kind'] == 'variable':
        if element['name'] in tainted:
            if top_var != '' and not top_var in tainted:
                tainted.append(top_var)
        if element['name'] in vars:
            varValue += vars[element['name']]
    elif element['kind'] == 'string':
        varValue += element['value']

    if 'left' in element:
        left = element['left']
        varValue += visit_bin_rec(left, tainted, top_var, vars)

    if 'right' in element:
        right = element['right']
        varValue += visit_bin_rec(right, tainted, top_var, vars)
    return varValue


def get_patterns(file_name: str) -> List[Pattern]:
    patterns = []
    with open(file_name, 'r') as file:
        for line in file:
            if line == '\n':
                pass
            else:
                patterns.append(Pattern(
                    vuln_type=line.strip('\n'),
                    entries=file.readline().strip('\n').split(','),
                    sanitizers=file.readline().strip('\n').split(','),
                    sinks=file.readline().strip('\n').split(',')
                ))

    return patterns


if __name__ == '__main__':
    if sys.version_info < (3, 6):
        raise ValueError('python >= 3.6 required')

    analysis(sys.argv[1])
