#
# This file is part of snmpfwd software.
#
# Copyright (c) 2014-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/snmpfwd/license.html
#
import sys
import re
from snmpfwd import error
from pysnmp.proto.rfc1902 import OctetString

# Constants
SYMBOL_OPTION = ':'
SYMBOL_SECTION_BEGIN = '{'
SYMBOL_SECTION_END = '}'
SYMBOL_WORD = ''


class Scanner(object):
    def __init__(self):
        self.lines = None
        self.tokens = []
        self.index = 0
        self.length = 0

    def load(self, filename):
        try:
            self.lines = open(filename).readlines()
        except OSError:
            raise error.SnmpfwdError('cant open config file %s: %s' % (filename, sys.exc_info()[1]))

        self.tokens = []

        while self.lines:
            line = self.lines.pop(0)

            if line and line[0] == '#':
                continue

            tokens = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', line)
            for i in range(len(tokens)):
                if tokens[i] and tokens[i][0] == '"' and tokens[i][-1] == '"':
                    tokens[i] = tokens[i][1:-1]

            if not tokens or not tokens[0] or tokens[0][0] == '#':
                continue

            for token in tokens:
                # Figure out the grammar type of the token
                if token and token[-1] == SYMBOL_OPTION:
                    # It's an option
                    symbol = SYMBOL_OPTION

                    # Cut the trailing char from token
                    token = token[:-1]
                elif token == '{':
                    symbol = SYMBOL_SECTION_BEGIN
                elif token == '}':
                    symbol = SYMBOL_SECTION_END
                else:
                    symbol = SYMBOL_WORD

                # Attach read tokens to list of tokens
                self.tokens.append((token, symbol))

        self.index = 0
        self.length = len(self.tokens)

        return self
        
    def get_token(self):
        if self.index >= self.length:
            raise error.EofError()

        self.index += 1

        return self.tokens[self.index-1]
        
    def unget_token(self):
        if not self.index:
            raise error.SnmpfwdError('%s nothing to unget' % self)
        self.index -= 1
        

class Parser(object):
    """The parser class implements config file syntactic analysing. Its
       output is an almost AST. Config file syntax is as follows:
   
       <object-name>
       {
           [attribute-name: [attribute-value]
           ...
       }
    """
    def __init__(self, scanner):
        self.scanner = scanner

    def load_section(self):
        obj = {'_name': '',
               '_children': []}

        state = 'FSM_START'
        
        while 1:
            # Initial state
            if state == 'FSM_START':
                try:
                    token, symbol = self.scanner.get_token()

                except error.EofError:
                    state = 'FSM_STOP'
                    continue

                self.scanner.unget_token()

                # See if it's object closure sign
                if symbol == SYMBOL_SECTION_END:
                    state = 'FSM_SECTION_END'

                # See if it's symbol sign
                elif symbol == SYMBOL_OPTION:
                    state = 'FSM_OPTION_NAME'

                # Default is to start from parsing up new section
                else:
                    state = 'FSM_SECTION_NAME'
                
            # If object name expected
            elif state == 'FSM_SECTION_NAME':
                self.scanner.get_token()

                self.scanner.unget_token()

                # Move to next FSM state
                state = 'FSM_SECTION_BEGIN'

            # If object body delimiter expected
            elif state == 'FSM_SECTION_BEGIN':
                self.scanner.get_token()

                # Get section begin
                token, symbol = self.scanner.get_token()

                # Now unget these tokens to be used at the
                # next FSM state
                self.scanner.unget_token()
                self.scanner.unget_token()

                # Make sure it's object's body start sign
                if symbol != SYMBOL_SECTION_BEGIN:
                    raise error.SnmpfwdError(
                        '%s missing object beginning sign: %s' % (self, token)
                        )

                state = 'FSM_CHILD_BEGIN'

            # If inclusive object expected
            elif state == 'FSM_CHILD_BEGIN':
                name, symbol = self.scanner.get_token()

                self.scanner.get_token()
                
                child_object = self.load_section()

                child_object['_name'] = name

                # Attach child object to the list of enclosed objects
                obj['_children'].append(child_object)

                state = 'FSM_CHILD_END'

            # If object body closure delimiter expected
            elif state == 'FSM_CHILD_END':
                # Get next token
                token, symbol = self.scanner.get_token()

                # Make sure it's object's body end sign
                if symbol != SYMBOL_SECTION_END:
                    raise error.SnmpfwdError(
                        '%s missing object closure sign: %s' % (self, token)
                        )
                    
                # Move to the beginning of FSM
                state = 'FSM_START'

            # If object body closure delimiter expected
            elif state == 'FSM_SECTION_END':
                # Get next token
                token, symbol = self.scanner.get_token()

                # Now unget token to be used at upper level FSM instance
                self.scanner.unget_token()

                # Make sure it's object's body end sign
                if symbol != SYMBOL_SECTION_END:
                    raise error.SnmpfwdError(
                        '%s missing object closure sign: %s' % (self, token)
                        )
                    
                # Move to next FSM state
                state = 'FSM_STOP'

            # If attribute name expected
            elif state == 'FSM_OPTION_NAME':
                # Get next token
                token, symbol = self.scanner.get_token()

                # See if this attribute does not yet exist
                if token in obj:
                    raise error.SnmpfwdError('%s multiple option occurrence: %s' % (self, token))
                    
                # Accept token as attribute name
                obj[token] = []

                # Now unget token to be used at the next FSM state
                self.scanner.unget_token()
                
                # Move to next FSM state
                state = 'FSM_OPTION_VALUE'

            # If option value expected
            elif state == 'FSM_OPTION_VALUE':
                option, symbol = self.scanner.get_token()

                # Read up one or more option values
                while 1:
                    try:
                        token, symbol = self.scanner.get_token()

                    except error.EofError:
                        state = 'FSM_STOP'
                        break

                    # If it's not a plain word
                    if symbol != SYMBOL_WORD:
                        self.scanner.unget_token()

                        # See if it's object begin symbol
                        if symbol == SYMBOL_SECTION_BEGIN:
                            # Unget section begin sign
                            self.scanner.unget_token()

                            # Remove previously added last value of
                            # the list as it turned to be section name
                            del obj[option][-1]

                        # Move to the beginning of FSM
                        state = 'FSM_START'
                        
                        break

                    # Accept token as attribute value
                    if token.lower()[:2] == '0x':
                        token = str(OctetString(hexValue=token[2:]))

                    obj[option].append(token)
                
            # If FSM is gonna stop
            elif state == 'FSM_STOP':
                # Return object loaded
                return obj

            # If this FSM state is not known
            else:
                raise error.SnmpfwdError('%s unknown FSM state: %s' % (self, state))

    def parse(self):
        try:
            return self.load_section()
        except error.EofError:
            raise error.SnmpfwdError('%s premature EOF while reading config file' % self)


class Config(object):
    def __init__(self):
        self.objects = {}
    
    def load(self, filename):
        self.objects = Parser(Scanner().load(filename)).parse()
        return self

    def traverse(self, objects, nodes):
        """Return the leaf object resulted by traversing config
           objects tree by nodes
        """
        for obj in objects:
            # Compare obj name with node name
#            if '_compiled_name' not in obj:
#                obj['_compiled_name'] = re.compile(obj['_name'])
#            if obj['_compiled_name'].match(nodes[0]):
            if obj['_name'] == nodes[0]:
                if len(nodes) == 1:
                    return obj
                r = self.traverse(obj['_children'], nodes[1:])
                if r is None:
                    return obj
                else:
                    return r

    def getPathsToAttr(self, attr, objects=None, nodes=None, paths=None):
        if objects is None:
            objects = self.objects
        if nodes is None:
            nodes = ()
        if paths is None:
            paths = []
        nodes += objects['_name'],
        if attr in objects:
            paths.append(nodes)
        for _objs in objects['_children']:
            self.getPathsToAttr(attr, _objs, nodes, paths)
        return paths

    def getAttrValue(self, attr, *nodes, **kwargs):
        scope = nodes
        while scope:
            obj = self.traverse([self.objects], scope)
            if obj and attr in obj:
                expect = kwargs.get('expect')

                if 'vector' in kwargs:
                    if expect:
                        try:
                            return [expect(x) for x in obj[attr]]
                        except Exception:
                            raise error.SnmpfwdError('%s value casting error at scope "%s" attribute "%s"' % (self, '.'.join(nodes), attr))
                    else:
                        return obj[attr]
                else:
                    if obj[attr]:
                        if expect:
                            try:
                                return expect(obj[attr][0])
                            except Exception:
                                raise error.SnmpfwdError('%s value casting error at scope "%s" attribute "%s"' % (self, '.'.join(nodes), attr))
                        else:
                            return obj[attr][0]
                    else:
                        return ''

            scope = scope[:-1]

        if 'default' in kwargs:
            return kwargs['default']
        else:
            raise error.SnmpfwdError('%s non-existing attribute "%s" at scope "%s"' % (self, attr, '.'.join(nodes)))
