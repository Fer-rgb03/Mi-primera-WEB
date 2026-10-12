import re
from collections import namedtuple
from flask import Flask, render_template, request

app = Flask(__name__)
# FASE 1: ANÁLISIS LÉXICO (Lexer)
Token = namedtuple('Token', ['type', 'value', 'line', 'column'])

def lexer(code):
    token_specification = [
        ('TIMESTAMP',  r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
        ('IP',         r'(\d{1,3}\.){3}\d{1,3}'),
        ('SEVERITY',   r'INFO|WARNING|ERROR|CRITICAL'),
        ('EVENT_TYPE', r'[A-Z]+(_[A-Z]+)*'),
        ('JSON_START', r'\{'),
        ('JSON_END',   r'\}'),
        ('STRING',     r'"[^"]*"'),
        ('COLON',      r':'),
        ('COMMA',      r','),
        ('NUMBER',     r'\d+'),
        ('SPACE',      r'[ \t]+'),
        ('NEWLINE',    r'\n'),
        ('MISMATCH',   r'.'),
    ]
    tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in token_specification)
    line_num = 1
    line_start = 0
    tokens = []

    for mo in re.finditer(tok_regex, code):
        kind = mo.lastgroup
        value = mo.group()
        column = mo.start() - line_start

        if kind == 'SPACE':
            continue
        elif kind == 'NEWLINE':
            line_start = mo.end()
            line_num += 1
            continue
        elif kind == 'MISMATCH':
            raise RuntimeError(f'Error Léxico: Caracter no reconocido {value!r} en la columna {column}')
        
        tokens.append(Token(kind, value, line_num, column))
    return tokens

# FASE 2: ANÁLISIS SINTÁCTICO (Parser)
class Parser:
    def __init__(self, tokens):
        self.tokens = list(tokens)
        self.pos = 0

    def match(self, expected_type):
        if self.pos < len(self.tokens) and self.tokens[self.pos].type == expected_type:
            token = self.tokens[self.pos]
            self.pos += 1
            return token
        actual = self.tokens[self.pos].type if self.pos < len(self.tokens) else "FIN_DE_CADENA"
        raise SyntaxError(f'Error Sintáctico: Se esperaba {expected_type} pero se detectó {actual}')

    def parse_log(self):
        timestamp = self.match('TIMESTAMP')
        ip = self.match('IP')
        severity = self.match('SEVERITY')
        event = self.match('EVENT_TYPE')
        self.parse_payload()
        return {
            "Fecha": timestamp.value,
            "IP Origen": ip.value,
            "Nivel": severity.value,
            "Evento": event.value
        }

    def parse_payload(self):
        self.match('JSON_START')
        if self.pos < len(self.tokens) and self.tokens[self.pos].type != 'JSON_END':
            self.parse_fields()
        self.match('JSON_END')

    def parse_fields(self):
        self.parse_field()
        while self.pos < len(self.tokens) and self.tokens[self.pos].type == 'COMMA':
            self.match('COMMA')
            self.parse_field()

    def parse_field(self):
        self.match('STRING')
        self.match('COLON')
        self.parse_value()

    def parse_value(self):
        current_type = self.tokens[self.pos].type
        if current_type == 'STRING':
            self.match('STRING')
        elif current_type == 'NUMBER':
            self.match('NUMBER')
        elif current_type == 'JSON_START':
            self.parse_payload()
        else:
             raise SyntaxError('El valor JSON debe ser un STRING, NUMBER o un sub-JSON.')


 #FASE 3: ENRUTAMIENTO WEB (Flask)

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado_sintactico = None
    error = None
    lista_tokens = []
    log_texto = ""

    if request.method == 'POST':
        log_texto = request.form.get('log_input', '')
        try:
            # 1. Ejecutar análisis léxico
            lista_tokens = lexer(log_texto)
            # 2. Ejecutar análisis sintáctico
            parser = Parser(lista_tokens)
            resultado_sintactico = parser.parse_log()
        except Exception as e:
            error = str(e)

    return render_template('index.html', 
                           log_texto=log_texto, 
                           tokens=lista_tokens, 
                           resultado=resultado_sintactico, 
                           error=error)

if __name__ == '__main__':
    app.run(debug=True)