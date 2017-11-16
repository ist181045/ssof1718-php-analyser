import json
import sys
from pattern import Pattern


def analysis(fileName):
    patterns = getPatterns("patterns")

    file = open(fileName, 'r')

    data = json.load(file)

    for pattern in patterns:
        tainted = []
        if data["kind"] == "program":
            for element in data["children"]:
                if element["kind"] == "assign":
                    right = element["right"]
                    if right["kind"] == "offsetlookup":
                        visitOffsetlookup(element, pattern, tainted)

                    if right["kind"] == "call":
                        visitCall(element, pattern, tainted)

                    if right["kind"] == "encapsed":
                        visitEncapsed(element, tainted)

                    if right["kind"] == "bin":
                        visitBin(element,tainted)



def visitOffsetlookup(element, pattern, tainted):
    right = element["right"]
    if "what" in right:
        what = right["what"]
        if what["kind"] == "variable":
            for entry in pattern.entries:
                if what["name"] == entry.strip("$"):
                    taint = element["left"]["name"]
                    if taint != "" and not taint in tainted:
                        tainted.append(taint)


def visitCall(element, pattern, tainted):
    right = element["right"]
    if "what" in right:
        what = right["what"]
        if what["kind"] == "identifier":
            what = right["what"]
            if what["kind"] == "identifier":
                for sensitiveSink in pattern.sensitiveSinks:
                    if what["name"] == sensitiveSink:
                        for argument in right["arguments"]:
                            if argument["name"] in tainted:
                                print("slice is vulnerable")
                for sanitization in pattern.sanitizations:
                    if what["name"] == sanitization:
                        for argument in right["arguments"]:
                            if argument["name"] in tainted:
                                tainted.remove(argument["name"])
    return ""


def visitEncapsed(element, tainted):
    right = element["right"]
    if "value" in right:
        for value in right["value"]:
            if "name" in value:
                if value["name"] in tainted:
                    if not element["left"]["name"] in tainted:
                        tainted.append(element["left"]["name"])


def visitBin(element, tainted):
    if "kind" in element["left"]:
        if element["left"]["kind"] == "variable":
            topVar = element["left"]["name"]
    else:
        return
    right = element["right"]
    if right["kind"] == "variable":
        if right["name"] in tainted:
            if topVar != "" and not topVar in tainted:
                tainted.append(topVar)
    if "left" in right:
        visitBinRec(right, tainted, topVar)


def visitBinRec(right, tainted, topVar):
    right = right["left"]["right"]
    if right["kind"] == "variable":
        if right["name"] in tainted:
            if topVar != "" and not topVar in tainted:
                tainted.append(topVar)
    if "left" in right:
        visitBinRec(right, tainted, topVar)


def getPatterns(fileName):
    file = open(fileName, 'r')
    patterns = []
    while True:
        type = file.readline()
        if type == "":
            break
        fileEntries = file.readline()
        entries = fileEntries.split(",")
        fileSanitizations = file.readline()
        sanitizations = fileSanitizations.split(",")
        fileSensitiveSinks = file.readline()
        sensitiveSinks = fileSensitiveSinks.split(",")
        file.readline()
        patterns.append(Pattern(type, entries, sanitizations, sensitiveSinks))
    return patterns


if __name__ == '__main__':
    analysis(sys.argv[1])
