import sys
import clang.cindex
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import TokenKind

CONT = 1
STOP = 2

def visit_node(node):

    for c in node.get_children():
        self.walk_tree(c)


class TreeWalker(object):

    def __init__(self):
        self.handlers = {}
        self.depth = -1 
        self.file_h = ""
        self.stack = []

    def set_visitor(self, kind, handler):
        self.handlers[kind] = handler

    def walk_tree(self, node):

        self.log("%s : %s"  % (node.kind, node.spelling))
        self.log("invalid " + "%s" % node.kind.is_invalid())
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
            if kind != TypeKind.CONSTANTARRAY:
                _type = node.type.spelling

                code = "%s %s" % (_type, name)
                if node.is_bitfield():
                    code += ":%u" % node.get_bitfield_width()
                code += ";\n"
                walker.write(code)

            else:
                # XXX
                _type = node.type.element_type.spelling
                size = node.type.get_array_size()
                walker.write("%s %s[%u];\n" % (_type, name, size))
                
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
        self.has_children = False
        super(self.__class__, self).__init__()

    def decl_struct_start(self, node, writer):

        if self.has_children:
            writer.write("struct %s {\n" % node.spelling)
        else:
            writer.write("struct %s" % node.spelling)

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
            walker.write("struct %s {\n" % node.spelling)
        else:
            self.decl_struct_start(node, walker)

        walker.visit_children(node)

        # TODO: no children used to detect forward declarations
        # zero length spelling used to detect anonymous structs
        # Is there any better way?
        if self.has_children:
            if len(node.spelling) > 0:
                walker.write("};\n");
            else:
                walker.write("}");
        else:
            walker.write_raw(";\n");
        
        return STOP

    def visit_field(self, node):

        self.log("in visit %s : %s"  % (node.kind, node.spelling))

        if node.kind == CursorKind.FIELD_DECL:
            for n in node.get_children():
                self.log("in visit %s : %s"  % (n.kind, n.spelling))

class TypedefVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()

    def __match_func_ptr(self, tokens):
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

    def __get_func_ptr_primitiv_ret(self, tokens):
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

    def visit(self, node, walker):

        name = node.spelling
        _type = None


        if node.type.get_canonical().kind == TypeKind.RECORD:
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
                    raise Exception("Typedef has more then one rec")

        elif node.type.get_canonical().kind == TypeKind.POINTER and \
                    self.__match_func_ptr(node.get_tokens()):

            params = []
            ret_type = None
            for x in node.get_children():
                # return type, if not primitive
                if x.kind == CursorKind.TYPE_REF:
                    ret_type = x.spelling
                else:
                    params.append("%s %s" % (x.type.spelling, x.spelling))

            if not ret_type:
                ret_type = self.__get_func_ptr_primitiv_ret(node.get_tokens())

            params = ', '.join(params)
            walker.write("typedef %s (*%s)(%s);\n" % (ret_type, name, params))
        else:
            # no ref, must be primitive
            print("AAAAA")
            print(node.type.get_canonical().kind)
            _type = None
            for x in node.get_children():
                _type = x.spelling

            if not _type:
                _type = node.type.get_canonical().spelling

            if node.type.get_canonical().kind == TypeKind.POINTER:
                _type += '*'

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

        walker.write("enum " + node.spelling + " {\n")

        # XXX: this does not expose the internals of the enumertion
        # and does not quite allow to gen nice indentions ...
        for x in node.get_children():
            tokens = map(lambda t: t.spelling, x.get_tokens())
            walker.write(' '.join(tokens) + ',\n')

        walker.write("};\n");
        
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

walker = TreeWalker()
walker.set_visitor(CursorKind.FIELD_DECL, field_visitor)
walker.set_visitor(CursorKind.STRUCT_DECL, struct_visitor)
walker.set_visitor(CursorKind.TYPEDEF_DECL, typedef_visitor)
walker.set_visitor(CursorKind.UNION_DECL, UnionVisitor())
walker.set_visitor(CursorKind.ENUM_DECL, EnumVisitor())
walker.visit(tu.cursor)

print "------------ CODE ------------"
print walker.file_h


