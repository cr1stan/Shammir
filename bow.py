import hashlib
from cryptography.fernet import Fernet
import random
import base64
from sympy import Symbol
from sympy import Integer
import os
import argparse

def convierte256(contraseña):
   if contraseña == None:
    print("Su contraseña al menos debe tener un caracter")
   clave = hashlib.sha256(contraseña.encode()).digest()
    #clave.update(contraseña.encode('utf-8'))
    #return int(clave.hexdigest(),16)
   return base64.urlsafe_b64encode(clave[:32])

'''
@param: contraseña. Solo se aceptarán constraseñas no nulas.
Lontraseña será transformada en un codigo en base64 puesto que para codificar un archivo se requieres en esta base
'''

def to_dec(num64):
   return int.from_bytes(base64.urlsafe_b64decode(num64), byteorder='big')

'''
@param numero. Recibe una cadena o texto en base64 paratransformlarla en decimal 
'''

def to64(num10):
   num64 = num10.to_bytes(32,byteorder='big')
   return base64.urlsafe_b64encode(num64)

def genera_polinomio(grado, contraseña): # el grado hace ilusion al numero de coeficientes que habra a0, a1, a2 ... es el grado menos 1
   if grado < 2:
    print("Este polinomio almenos debe tener 2 coeficientes")
   coef = [] 
   for i in range(grado-1):
      coef.append(random.randint(1, 10))
   coef.append(contraseña) 
   return coef 

'''
@param: numero de coeficientes y contraseña. Se generará una lista que simboliza un polinomio 
con la cantidad de coeficientes equivalentes al grado (los coeficientes se generaran aleatoriamente)
y en el termino independiente se colocará la contraseña en binario (para poder operar)  
'''

def evaluar(numero, polinomio):  
   contador = 0
   t = len(polinomio)-1
   for i in range(len(polinomio)):
      contador = contador + ((numero ** t) * polinomio[i])
      t = t-1
   return contador

'''
@param un numero entero y una lista: Recibirá un polinomio y un numero, deacuerdo a la lista y el numero de coeficientes,
retornará un entero, resultado de evaluar numero en el polinomio 
'''

'''
def guarda_polinomio(dec):
    polinomio =genera_polinomio(3, dec)   
    with open ('polinomio.txt', 'w') as file:        #prueba para intentar generar un polinomio
        for i in range(len(polinomio)):
         file.write(str(polinomio[i]) + '\n')
'''

def genera_frags(polinomio):
   eva = 1
   with open('fragmentos.frags', 'w') as file: 
      for i in range(len(polinomio)):
         file.write(str(eva) + " " +  str(evaluar(eva, polinomio)) + '\n')
         eva = eva + 1

'''
@param: lista de coef que simboliza el polinomio. Se generará un archivo .frags que contendrá las n evaluaciones 
del mismo
'''

      
def interpolación(archivo):
   parejas =[]
   labrange = []
   n = Symbol('n')

   with open(archivo, 'r') as file:
      for linea in file:
         x, y = map(int, linea.strip().split())  
         parejas.append((x, y))    
   
   for i in range(len(parejas)):
      seg  = parejas[i][1]      
      prim = parejas[i][0]
      producto = 1  
      for j in range(len(parejas)):     
         if i != j:           
            producto = producto * ((n-parejas[j][0])/(prim - parejas[j][0]))
      resultado = seg * producto
      labrange.append(resultado)
    
   sumatoria = 0
   
   for k in range(len(labrange)):
      evaluacion = labrange[k].subs(n, 0)
      sumatoria = sumatoria + evaluacion              

   return int(sumatoria)

'''
@param: archivo.frags. Dado un archivo con las n evaluaciones de un coeficientes se puede 
devolverá el número evaluado en 0 (la contraseña en base decimal) usando la interpolacion de Labrange

'''


def genera_clave(contraseña):
    clave_hash = convierte256(contraseña)
    with open ("clave_secreta.txt", 'wb')as file:
        file.write(clave_hash)


def codificar(archivo, contraseña):
  f = Fernet(convierte256(contraseña))  
  nombre, tipo = os.path.splitext(archivo)
  encriptado =  f"{nombre}.aes"
  #genera_clave(contraseña)
  genera_frags(genera_polinomio(random.randint(2,5), to_dec(convierte256(contraseña))))
  with open (archivo, 'rb') as file:
      info = file.read()
  encriptacion = f.encrypt(info)
  with open (encriptado, "wb") as file:
      file.write(encriptacion) 


def descodificar(archivo_codificado, fragmentos):    
    nombre, tipo = os.path.splitext(archivo_codificado)
    decodificado = f"{nombre + "_" + "decodificado"}.txt"
    clave = to64(interpolación(fragmentos))
    f = Fernet(clave)
    with open(archivo_codificado, 'rb') as file:
        info_encriptada = file.read()
        info_desencriptada = f.decrypt(info_encriptada)
    with open (decodificado, 'wb') as file:
        file.write(info_desencriptada)




#pol = genera_polinomio(3,57)
#print(pol)
#print(evaluar(1, pol))
#generadortxt(pol)

#codificar('mis claves nucleares.txt', "amigo578")
#descodificar('texto_encriptado.aes', "T_iVR4LhLjebPrwyBbbYlcAScbjgDesKNuhmURIsOSU=")
#guarda_polinomio("5")
#codificar('mis claves nucleares.txt', "chicos quiero mortadela")

#codificar('mis claves nucleares.txt', "chicos estoy comiendo mortadela")#
#descodificar('mis claves nucleares.aes', 'fragmentos.frags' )
#print(to_dec('rhk0mys3_5wsX3chFzng8G1aiCODWHNwFdFb63SqBPg='))
#print(to64(interpolación('fragmentos.frags')))

if __name__ == "__main__":
   parser = argparse.ArgumentParser(description="Codificar en aes un documento con una contraseña")
   parser.add_argument("-c", "--codificar", help="Se codificará el documento en aes", action="store_true")
   parser.add_argument("--archivo", help="nombre o ruta del archivo")
   parser.add_argument("--contraseña", help="proporciona una contraseña")

   parser.add_argument("-d", "--decodificar", help="Decodificar con interpolacion el archivo archivo.aes", action='store_true')
   parser.add_argument("--archivo_codificado", help="Ruta del archivo.AES")
   parser.add_argument("--fragmentos", help="Ruta del archivo.frags con la n interpolaciones lineales")  
   args =parser.parse_args()
   

   if args.codificar:
      if args.archivo and args.contraseña:
         codificar(args.archivo, args.contraseña)
      else:
         print("Falta algun argumento")


   
   elif args.decodificar:
      if args.archivo_codificado and args.fragmentos:
         descodificar(args.archivo_codificado, args.fragmentos)
      else:
         print("Falta el archivo.aes o el archivo.grags")  
         


        

   









