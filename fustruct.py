import sys
import clang.cindex
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import TokenKind

CONT = 1
STOP = 2

'''
XXX:
Refactor handling of function pointers. (now it is just copy/paste)
Get rid of long attribute access node.get_canonical().type.kind.
'''

def match_func_ptr(tokens):
    '''
    XXX: there should be a better way
    we search for pattern (...)(...) in typedef,
    if it has it then we conclude that this is 
    a function pointer typedef
    '''

    stack = []
    count = 0

    for t in tokens:
        if t.kind == TokenKind.PUNCTUATION:
            if t.spelling == '(':
                stack.append('(')
            elif t.spelling == ')':
                prev = stack.pop()
                if prev != '(':
                    return False

                if len(stack) == 0:
                    count += 1

                if count > 2:
                    return False

    return (count == 2)


def get_func_ptr_primitiv_ret(tokens):
    '''
    XXX: there should be a better way

    We parse the tokens to get the return type for
    a function pointer since for some reason it does
    not appear in children
    '''

    result = ""
    for t in tokens:

        if t.spelling == 'typedef':
            continue

        if t.spelling != '(':
            result += t.spelling + " "
        else:
            break

    return result

def visit_node(node):

    for c in node.get_children():
        self.walk_tree(c)


class TreeWalker(object):

    def __init__(self, debug=False):
        self.handlers = {}
        self.depth = -1 
        self.file_h = ""
        self.stack = []
        self.debug = debug
        # XXX: could not find a better way to handle typdefed enums
        # it seems that we should be able to use underlying_typedef_type
        # on children (judging by clang ast output), but children in python
        # have type ENUM_DECL instead of ENUM_CONSTANT_DECL, may be 
        # there is something wrong with python bindings.

        # a list of nodes we saw no as part of an enum
        self.anon_enums = []
        # a list of constants declared via enum and typedef
        self.enum_consts = []

    def add_anon_enum(self, node):
        self.anon_enums.append(node)

    def add_anon_enum_const(self, node):
        self.enum_consts.append(node)

    def gen_anon_enums(self):
        '''
        Generates code for anonymous enum constants which 
        were not afterwards declared via typedef.

        XXX: After some trials it turned out that if we have a constant
        in anon enum defined out of typedef it does not appear in any
        other typedefed anonymous enum in case of redefinition.
        '''

        for node in self.anon_enums:

            code = 'enum {\n'
            defined = 0

            for x in node.get_children():

                if x.spelling in self.enum_consts:
                    break

                defined += 1
                tokens = map(lambda t: t.spelling, x.get_tokens())
                code += ' '.join(tokens) + ',\n'
            
            if defined > 0:
                code += '};\n'
                self.file_h = code + self.file_h

    def set_visitor(self, kind, handler):
        self.handlers[kind] = handler

    def walk_tree(self, node):

        if self.debug:
            self.log("%s : %s"  % (node.kind, node.spelling))
            #self.log("invalid " + "%s" % node.kind.is_invalid())
            self.log("type " + "%s" % node.type.kind)
        #if node.referenced:
        #    self.log("ref " + "%s" % node.referenced.spelling)
        #self.log("attr " + "%s" % node.kind.is_attribute())
        #self.log("decl " + "%s" % node.kind.is_declaration())
        #self.log("align " + "%s" % node.type.get_align())
        #self.log("align " + "%s" % node.type.get_canonical().get_align())

        if node.kind in self.handlers:
            self.depth += 1
            ret = self.handlers[node.kind](node, self)
            self.depth -= 1
            if ret != CONT:
                return

        self.depth += 1
        for c in node.get_children():
            self.walk_tree(c)
        self.depth -= 1

    def visit(self, node):
        self.walk_tree(node)

    def visit_children(self, node):
        for c in node.get_children():
            self.walk_tree(c)

    def log(self, msg):
        print self.depth*'\t' + ("%s" % msg)

    def write(self, data):
        self.file_h += self.depth*'\t' + data

    def write_raw(self, data):
        self.file_h += data

    def push(self, data):
        self.stack.append(data)

    def pop(self, data):
        self.stack.pop(data)

class Visitor(object):

    def __init__(self):
        pass

    def __call__(self, node, walker):
        ret = self.visit(node, walker)
        return ret

    def visit(node, walker):
        return CONT

class FieldVisitor(Visitor):

    def __init__(self):
        pass

    def visit(self, node, walker):
        '''
        We stop this one, cause in case of defining
        string during field declaration we get all the
        struct nodes as field children
        '''

        name = node.spelling
        _type = None
        kind = node.type.get_canonical().kind

        if  kind != TypeKind.RECORD:
            
            code = ''

            if kind == TypeKind.CONSTANTARRAY:
                # XXX
                if node.type.kind ==  TypeKind.CONSTANTARRAY:
                    _type = node.type.get_array_element_type().spelling
                else:
                    _type = node.type.get_canonical().get_array_element_type().spelling

                size = node.type.get_canonical().get_array_size()
                code = "%s %s[%u];" % (_type, name, size)

            elif kind == TypeKind.INCOMPLETEARRAY:

                if node.type.kind ==  TypeKind.INCOMPLETEARRAY:
                    _type = node.type.get_array_element_type().spelling
                else:
                    _type = node.type.get_canonical().get_array_element_type().spelling

                _type = node.type.get_canonical().element_type.spelling
                code = "%s %s[];" % (_type, name)

            elif kind == TypeKind.POINTER and \
                    match_func_ptr(node.get_tokens()):

                params = []
                ret_type = None
                for x in node.get_children():
                    # return type, if not primitive
                    if x.kind == CursorKind.TYPE_REF:
                        ret_type = x.spelling
                    else:
                        params.append("%s %s" % (x.type.spelling, x.spelling))

                if not ret_type:
                    ret_type = get_func_ptr_primitiv_ret(node.get_tokens())

                params = ', '.join(params)
                code = "%s (*%s)(%s);" % (ret_type, name, params)

            else: 
                _type = node.type.spelling

                code = "%s %s" % (_type, name)
                if node.is_bitfield():
                    code += ":%u" % node.get_bitfield_width()
                #code += "; // %02X\n" % (node.get_field_offsetof()/8)
                code += "; "

            code += " //%02X\n" % (node.get_field_offsetof()/8)
            walker.write(code)
                
        else:
            # in case we have nested struct definitions,
            # the very last one is going to reflect the 
            # actual type
            for x in node.get_children():
                    _type = x.spelling
                    if len(_type) == 0:
                        x.force = True
                        walker.visit(x) 

            if len(_type) > 0:
                walker.write("%s %s;\n" % (_type, name))
            else:
                # anon struct
                walker.write_raw(" %s;\n" % name)

        return STOP

class StructVisitor(Visitor):

    def __init__(self):
        # as the result we generate a header with all the structures and 
        # typedef 
        self.struct_h = ""
        super(self.__class__, self).__init__()

    def decl_struct_start(self, node, writer, has_children):

        if has_children:
            writer.write("struct %s {\n" % node.spelling)
        else:
            writer.write("struct %s" % node.spelling)

    def visit(self, node, walker):

        has_children = False
        force = False
        if hasattr(node, 'force'):
            force = node.force

        if len(node.spelling) == 0 and not force:
            return STOP

        for c in node.get_children():
            has_children = True

        if force:
            walker.write("struct %s {\n" % node.spelling)
        else:
            self.decl_struct_start(node, walker, has_children)

        walker.visit_children(node)

        # TODO: no children used to detect forward declarations
        # zero length spelling used to detect anonymous structs
        # Is there any better way?
        if has_children:
            if len(node.spelling) > 0:
                walker.write("};\n");
            else:
                walker.write("}");
        else:
            walker.write_raw(";\n");

        return STOP

class TypedefVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()



    def visit(self, node, walker):

        name = node.spelling
        _type = None

        kind = node.type.get_canonical().kind

        if kind == TypeKind.RECORD:
            walker.write("typedef \n")
            for x in node.get_children():
                if not _type:
                    _type = x.spelling
                    # anonymous struct/union typedef
                    if len(_type) == 0:
                        x.force = True
                        walker.visit(x) 
                        walker.write(" %s;\n" % name)
                        return STOP
                    else:
                        walker.write("%s %s;\n" % (_type, name))
                else:
                    raise Exception("Typedef has more then one rec")

        elif kind == TypeKind.ENUM:
            walker.write("typedef \n")

            for x in node.get_children():
                if x.kind == CursorKind.ENUM_DECL:
                    _type = x.spelling

                    if len(_type) == 0:
                        x.force = True
                        walker.visit(x)
                        walker.write(" %s;\n" % name)
                        return STOP
                    else:
                        walker.write("enum %s %s;\n" % (_type, name))

                elif x.kind == CursorKind.TYPE_REF:
                    walker.write("enum %s %s;\n" % (x.spelling, name))

        elif node.type.get_canonical().kind == TypeKind.POINTER and \
                    match_func_ptr(node.get_tokens()):

            params = []
            ret_type = None
            for x in node.get_children():
                # return type, if not primitive
                if x.kind == CursorKind.TYPE_REF:
                    ret_type = x.spelling
                else:
                    params.append("%s %s" % (x.type.spelling, x.spelling))

            if not ret_type:
                ret_type = get_func_ptr_primitiv_ret(node.get_tokens())

            params = ', '.join(params)
            walker.write("typedef %s (*%s)(%s);\n" % (ret_type, name, params))

        elif node.type.get_canonical().kind == TypeKind.CONSTANTARRAY:

            size = node.type.get_canonical().get_array_size()

            _type = None
            for x in node.get_children():
                if x.kind == CursorKind.TYPE_REF:
                    _type = x.spelling

            if not _type:
                _type = node.type.get_canonical().element_type.spelling
            else:
                # XXX: there is probably a way to sort out the pointers
                # via TYPE_REF or something, but for know we just resolv
                # the type to the primitive and add those nested pointers
                # since I did not want to spend any more time on this ...
                elem_type = node.type.get_canonical().element_type
                type_string = ''

                while elem_type.kind == TypeKind.POINTER and elem_type.get_pointee():
                    elem_type = elem_type.get_pointee()
                    type_string += ' *'

                if len(type_string) > 0:
                    _type = elem_type.spelling + type_string

            walker.write("typedef %s %s[%u];\n" % (_type, name, size))

        elif node.type.get_canonical().kind == TypeKind.INCOMPLETEARRAY:
                _type = node.type.get_canonical().element_type.spelling
                walker.write("typedef %s %s[];\n" % (_type, name))
        else:
            # no ref, must be primitive
            _type = None
            for x in node.get_children():
                if x.kind == CursorKind.TYPE_REF:
                    _type = x.spelling

            if not _type:
                # primitive is going to be resolved and
                # spelled fully, so no need for a star in pointers
                _type = node.type.get_canonical().spelling
            else:
                if node.type.get_canonical().kind == TypeKind.POINTER:
                    _type += ' *'

            code = "typedef %s %s" % (_type, name)
            align = node.type.get_align()

            if align != node.type.get_canonical().get_align():
                code += " __attribute__((aligned(%u)))" % align

            walker.write("%s;\n" % code)

        return STOP

class UnionVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()

    def decl_union_start(self, node, writer):

        if self.has_children:
            writer.write("union %s {\n" % node.spelling)
        else:
            writer.write("union %s" % node.spelling)

    def visit(self, node, walker):

        force = False
        if hasattr(node, 'force'):
            force = node.force

        if len(node.spelling) == 0 and not force:
            return STOP

        for c in node.get_children():
            self.has_children = True
            break

        if force:
            walker.write("union %s {\n" % node.spelling)
        else:
            self.decl_union_start(node, walker)

        walker.visit_children(node)

        if self.has_children:
            if len(node.spelling) > 0:
                walker.write("};\n");
            else:
                walker.write("}");
        else:
            walker.write_raw(";\n");

        return STOP

class EnumVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()

    def visit(self, node, walker):

        has_children = False
        force = False

        if hasattr(node, 'force'):
            force = node.force

        # XXX: How to tell the difference between anon enum
        # declaration enum {a=1}; 
        #  and
        # typedef enum {b=1} enm_t?
        # For now just store all the not forced once in a list
        # and at the end check if the named 
        # constants from enum where declared or not via typedef

        if len(node.spelling) == 0 and not force:
            walker.add_anon_enum(node)
            return STOP

        walker.write("enum " + node.spelling + " {\n")

        # XXX: this does not expose the internals of the enumertion
        # and does not quite allow to gen nice indentions ...
        for x in node.get_children():
            has_children = True
            walker.add_anon_enum_const(x.spelling)
            tokens = map(lambda t: t.spelling, x.get_tokens())
            walker.write(' '.join(tokens) + ',\n')

        if has_children:
            if len(node.spelling) > 0:
                walker.write("};\n");
            else:
                walker.write("}\n");
        else:
            walker.write_raw(";\n");

        return STOP

# we just need this to skip visiting
# struct/classes declarations referenced 
# from variable declarations 
class VarVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()

    def visit(self, node, walker):
        return STOP



clang.cindex.Config.set_library_path("/Library/Developer/CommandLineTools/usr/lib")

index = clang.cindex.Index.create()
#tu = index.parse(sys.argv[1])
tu = index.parse(sys.argv[1], ['-x', 'c++'])


struct_visitor = StructVisitor()
typedef_visitor = TypedefVisitor()
field_visitor = FieldVisitor()

#clang.cindex.Cursor_visit(tu.cursor, 
#        clang.cindex.Cursor_visit_callback(struct_visitor.visit), None)

#walker = TreeWalker(True)
walker = TreeWalker(False)
walker.set_visitor(CursorKind.FIELD_DECL, field_visitor)
walker.set_visitor(CursorKind.STRUCT_DECL, struct_visitor)
walker.set_visitor(CursorKind.TYPEDEF_DECL, typedef_visitor)
walker.set_visitor(CursorKind.UNION_DECL, UnionVisitor())
walker.set_visitor(CursorKind.ENUM_DECL, EnumVisitor())
walker.set_visitor(CursorKind.VAR_DECL, VarVisitor())
walker.visit(tu.cursor)
walker.gen_anon_enums()

print walker.file_h


