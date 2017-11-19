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
            vars[left['name']] = \
                visit_assign_offsetlookup(element, pattern, tainted)

        if right['kind'] == 'call':
            visit_assign_call(element, pattern, tainted, vars)

        if right['kind'] == 'encapsed':
            vars[left['name']] = visit_encapsed(element, tainted,
                                                vars)

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
                visit_offsetlookup(argument, pattern)

    if element['kind'] == 'call':
        visit_call(element, pattern, tainted)

    if element['kind'] == 'if':
        visit_if(element, pattern, tainted, vars)

    if element['kind'] == 'while':
        visit_while(element, pattern, tainted, vars)


def visit_left_test(left: dict) -> dict:
    test_left = {}
    if left['kind'] == 'variable':
        test_left['variable'] = left['name']
    elif left['kind'] == 'string':
        test_left['string'] = left['value']
    return test_left


def visit_right_test(right: dict) -> dict:
    test_right = {}
    if right['kind'] == 'variable':
        test_right['variable'] = right['name']
    elif right['kind'] == 'string':
        test_right['string'] = right['value']
    return test_right


def visit_if(element: dict, pattern: Pattern, tainted: list,
             vars: dict) -> None:
    test = element['test']

    if test['type'] == '==':
        test_left = visit_left_test(test['left'])
        test_right = visit_right_test(test['right'])

        if 'variable' in test_left and 'string' in test_right:
            if test_left['variable'] not in vars:
                visit_main_if_block(element['body'], pattern, tainted, vars)
                visit_alternate(element['alternate'], pattern, tainted, vars)

            elif vars[test_left['variable']] == test_right:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)

        elif 'string' in test_left and 'variable' in test_right:
            if test_right['variable'] not in vars:
                visit_main_if_block(element['body'], pattern, tainted, vars)
                visit_alternate(element['alternate'], pattern, tainted, vars)

            elif test_left == vars[test_right['variable']]:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)

        elif 'variable' in test_left and 'variable' in test_right:
            if test_left['variable'] not in vars \
                    or test_right['variable'] not in vars:
                visit_main_if_block(element['body'], pattern, tainted, vars)
                visit_alternate(element['alternate'], pattern, tainted, vars)

            elif vars[test_left['variable']] == \
                    vars[test_right['variable']]:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)

        elif 'string' in test_left and 'string' in test_right:
            if test_left == test_right:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)


    elif test['type'] == '!=':
        test_left = visit_left_test(test['left'])

        test_right = visit_right_test(test['right'])

        if 'variable' in test_left and 'string' in test_right:
            if test_left['variable'] not in vars:
                visit_main_if_block(element['body'], pattern, tainted, vars)
                visit_alternate(element['alternate'], pattern, tainted, vars)

            elif vars[test_left['variable']] != test_right:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)

        elif 'string' in test_left and 'variable' in test_right:
            if test_right['variable'] not in vars:
                visit_main_if_block(element['body'], pattern, tainted, vars)
                visit_alternate(element['alternate'], pattern, tainted, vars)

            elif test_left == vars[test_right['variable']]:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)

        elif 'variable' in test_left and 'variable' in test_right:
            if test_left['variable'] not in vars or test_right[
                'variable'] not in vars:
                visit_main_if_block(element['body'], pattern, tainted, vars)
                visit_alternate(element['alternate'], pattern, tainted, vars)

            elif vars[test_left['variable']] != vars[test_right['variable']]:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)

        elif 'string' in test_left and 'string' in test_right:
            if test_left != test_right:
                visit_main_if_block(element['body'], pattern, tainted, vars)

            else:
                visit_alternate(element['alternate'], pattern, tainted, vars)


def visit_main_if_block(body: dict, pattern: Pattern, tainted: list,
                        vars: dict) -> None:
    for child in body['children']:
        visit_element(child, pattern, tainted, vars)


def visit_alternate(alternate: dict, pattern: Pattern, tainted: list,
                    vars: dict) -> None:
    if alternate is not None:
        if alternate['kind'] == 'if':
            visit_if(alternate, pattern, tainted, vars)
        else:
            for child in alternate['children']:
                visit_element(child, pattern, tainted, vars)


def visit_while(element: dict, pattern: Pattern, tainted: list,
                vars: dict) -> None:
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

    if top_change and top_var in vars:
        if test_type == '!=':
            visit_while_diff_test(body, pattern, tainted, vars, top_var,
                                  test_right)
        elif test_type == '==':
            visit_while_equal_test(body, pattern, tainted, vars, top_var,
                                   test_right)

    elif top_change and top_var not in vars:
        vars[top_var] = ""
        if test_type == '!=':
            visit_while_diff_test(body, pattern, tainted, vars, top_var,
                                  test_right)
        elif test_type == '==':
            visit_while_equal_test(body, pattern, tainted, vars, top_var,
                                   test_right)
        vars[top_var] = "notEmpty"
        if test_type == '!=':
            visit_while_diff_test(body, pattern, tainted, vars, top_var,
                                  test_right)
        elif test_type == '==':
            visit_while_equal_test(body, pattern, tainted, vars, top_var,
                                   test_right)


def visit_while_diff_test(body: dict, pattern: Pattern, tainted: list,
                          vars: dict, top_var: str, test_right) -> None:
    while vars[top_var] != test_right:
        initial = vars[top_var]

        for children in body['children']:
            visit_element(children, pattern, tainted, vars)

        if initial == vars[top_var]:
            break


def visit_while_equal_test(body: dict, pattern: Pattern, tainted: list,
                           vars: dict, top_var: str, test_right) -> None:
    while vars[top_var] == test_right:
        initial = vars[top_var]

        for children in body['children']:
            visit_element(children, pattern, tainted, vars)

        if initial == vars[top_var]:
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
                      vars: dict) -> str:
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
                    if left_var in vars:
                        vars[left_var] = vars[left_var][1:]

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


def visit_encapsed(element: dict, tainted: list, vars: dict) -> str:
    right = element['right']
    val = ''

    if 'value' in right:
        for value in right['value']:
            if 'name' in value:
                if value['name'] in tainted:
                    if not element['left']['name'] in tainted:
                        tainted.append(element['left']['name'])
                if value['name'] in vars:
                    val += vars[value['name']]
            elif value['kind'] == 'string':
                val += value['value']

    return val


def visit_bin(element: dict, tainted: list, vars: dict) -> Union[str, None]:
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
        if right['name'] in vars:
            val += vars[right['name']]
    elif right['kind'] == 'string':
        val += right['value']

    if 'left' in right:
        val += visit_bin_rec(right, tainted, top_var, vars)

    return val


def visit_bin_rec(element: dict, tainted: list, top_var: dict,
                  vars: dict) -> str:
    val = ''

    if element['kind'] == 'variable':
        if element['name'] in tainted:
            if top_var is not None and top_var not in tainted:
                tainted.append(top_var)

        if element['name'] in vars:
            val += vars[element['name']]

    elif element['kind'] == 'string':
        val += element['value']

    if 'left' in element:
        left = element['left']
        val += visit_bin_rec(left, tainted, top_var, vars)

    if 'right' in element:
        right = element['right']
        val += visit_bin_rec(right, tainted, top_var, vars)

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
