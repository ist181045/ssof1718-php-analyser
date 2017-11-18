#!/usr/bin/env python3.6

import json
import sys
from os.path import dirname, realpath
from typing import List, Union

from pattern import Pattern


def analysis(file: str) -> None:
    patterns = get_patterns(
        '{base}/patterns'.format(base=dirname(realpath(__file__))))

    with open(file, 'r') as json_slice:
        ast = json.load(json_slice)

    for pattern in patterns:
        tainted = []
        variables = {}

        if ast['kind'] == 'program':
            for element in ast['children']:
                visit_element(element, pattern, tainted, variables)


def visit_element(element: dict, pattern: Pattern, tainted: list,
                  variables: dict) -> None:
    if element['kind'] == 'assign':
        left = element['left']
        right = element['right']

        if right['kind'] == 'offsetlookup':
            variables[left['name']] = \
                visit_assign_offsetlookup(element, pattern, tainted)

        if right['kind'] == 'call':
            visit_assign_call(element, pattern, tainted, variables)

        if right['kind'] == 'encapsed':
            variables[left['name']] = visit_encapsed(element, tainted,
                                                     variables)

        if right['kind'] == 'bin':
            variables[left['name']] = visit_bin(element, tainted, variables)

        if left['kind'] == 'variable':
            if right['kind'] == 'variable':
                if right['name'] in tainted:
                    if left['name'] not in tainted:
                        tainted.append(left['name'])
                if right['name'] in variables:
                    variables[left['name']] = variables[right['name']]

            if right['kind'] == 'string':
                variables[left['name']] = right['value']

    if element['kind'] in pattern.sinks:
        arguments = element['arguments']
        for argument in arguments:
            if argument['kind'] == 'offsetlookup':
                visit_offsetlookup(argument, pattern)

    if element['kind'] == 'call':
        visit_call(element, pattern, tainted)

    if element['kind'] == 'if':
        visit_if(element, pattern, tainted, variables)

    if element['kind'] == 'while':
        visit_while(element, pattern, tainted, variables)


def visit_if(element: dict, pattern: Pattern, tainted: list,
             variables: dict) -> None:
    body = element['body']
    for child in body['children']:
        visit_element(child, pattern, tainted, variables)

    alternate = element['alternate']
    if alternate is not None:
        if alternate['kind'] == 'if':
            visit_if(alternate, pattern, tainted, variables)
        else:
            for child in alternate['children']:
                visit_element(child, pattern, tainted, variables)


def visit_while(element: dict, pattern: Pattern, tainted: list,
                variables: dict) -> None:
    top_var = None
    test_type = None
    test_right = None
    top_change = None

    test = element['test']
    if test['kind'] == 'bin':
        top_var = test['left']['name']
        test_type = test['type']
        test_right = test['right']['value']
        top_change = False

    body = element['body']
    for children in body['children']:
        if 'left' in children:
            if children['left']['name'] == top_var:
                top_change = True

    if top_change and top_var in variables:
        if test_type == '!=':
            visit_while_diff_test(body, pattern, tainted, variables, top_var,
                                  test_right)
        elif test_type == '==':
            visit_while_equal_test(body, pattern, tainted, variables, top_var,
                                   test_right)

    elif top_change and top_var not in variables:
        variables[top_var] = ""
        if test_type == '!=':
            visit_while_diff_test(body, pattern, tainted, variables, top_var,
                                  test_right)
        elif test_type == '==':
            visit_while_equal_test(body, pattern, tainted, variables, top_var,
                                   test_right)
        variables[top_var] = "notEmpty"
        if test_type == '!=':
            visit_while_diff_test(body, pattern, tainted, variables, top_var,
                                  test_right)
        elif test_type == '==':
            visit_while_equal_test(body, pattern, tainted, variables, top_var,
                                   test_right)


def visit_while_diff_test(body: dict, pattern: Pattern, tainted: list,
                          variables: dict, top_var: str, test_right) -> None:
    while variables[top_var] != test_right:
        initial = variables[top_var]

        for children in body['children']:
            visit_element(children, pattern, tainted, variables)

        if initial == variables[top_var]:
            break


def visit_while_equal_test(body: dict, pattern: Pattern, tainted: list,
                           variables: dict, top_var: str, test_right) -> None:
    while variables[top_var] == test_right:
        initial = variables[top_var]

        for children in body['children']:
            visit_element(children, pattern, tainted, variables)

        if initial == variables[top_var]:
            break


def visit_offsetlookup(argument: dict, pattern: Pattern) -> None:
    if 'what' in argument:
        what = argument['what']

        for entry in pattern.entries:
            if what['name'] == entry.strip('$'):
                alert(pattern)


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


def visit_assign_call(element: dict, pattern: Pattern, tainted: list,
                      variables: dict) -> str:
    right = element['right']

    if 'what' in right:
        what = right['what']
        if what['kind'] == 'identifier':
            for sink in pattern.sinks:
                if what['name'] == sink:
                    for argument in right['arguments']:
                        if argument['name'] in tainted:
                            alert(pattern)

            for sanitizer in pattern.sanitizers:
                if what['name'] == sanitizer:
                    for argument in right['arguments']:
                        if argument['name'] in tainted:
                            tainted.remove(argument['name'])

            if what['name'] == 'substr':
                if element['left']['kind'] == 'variable':
                    left_var = element['left']['name']
                    if left_var in variables:
                        variables[left_var] = variables[left_var][1:]

    return ''


def visit_call(element: dict, pattern: Pattern, tainted: list) -> None:
    if 'what' in element:
        what = element['what']
        for sink in pattern.sinks:
            if what['name'] == sink:
                for argument in element['arguments']:
                    if 'name' in argument:
                        if argument['name'] in tainted:
                            alert(pattern)


def visit_encapsed(element: dict, tainted: list, variables: dict) -> str:
    right = element['right']
    val = ''

    if 'value' in right:
        for value in right['value']:
            if 'name' in value:
                if value['name'] in tainted:
                    if not element['left']['name'] in tainted:
                        tainted.append(element['left']['name'])
                if value['name'] in variables:
                    val += variables[value['name']]
            elif value['kind'] == 'string':
                val += value['value']

    return val


def visit_bin(element: dict, tainted: list,
              variables: dict) -> Union[str, None]:
    val = ''
    top_var = None

    if 'kind' in element['left']:
        if element['left']['kind'] == 'variable':
            top_var = element['left']['name']
    else:
        return

    right = element['right']
    if right['kind'] == 'variable':
        if right['name'] in tainted:
            if top_var is not None and top_var not in tainted:
                tainted.append(top_var)
        if right['name'] in variables:
            val += variables[right['name']]
    elif right['kind'] == 'string':
        val += right['value']

    if 'left' in right:
        val += visit_bin_rec(right, tainted, top_var, variables)

    return val


def visit_bin_rec(element: dict, tainted: list, top_var: dict,
                  variables: dict) -> str:
    val = ''

    if element['kind'] == 'variable':
        if element['name'] in tainted:
            if top_var is not None and top_var not in tainted:
                tainted.append(top_var)

        if element['name'] in variables:
            val += variables[element['name']]

    elif element['kind'] == 'string':
        val += element['value']

    if 'left' in element:
        left = element['left']
        val += visit_bin_rec(left, tainted, top_var, variables)

    if 'right' in element:
        right = element['right']
        val += visit_bin_rec(right, tainted, top_var, variables)

    return val


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


def alert(pattern):
    print('Possible vulnerability detected: {type}'.format(type=pattern.type))
    print('Please consider sanitizing tainted code with one of the following:\n'
          + '- ', end='')
    print('\n- '.join([s for s in pattern.sanitizers]))
    sys.exit(1)


if __name__ == '__main__':
    if sys.version_info < (3, 6):
        raise ValueError('python >= 3.6 required')

    analysis(sys.argv[1])
    print('No vulnerability detected')
