Esta regla sirve para identificar muestras de la familia una vez desempaquetadas por lo que no se asegura su eficacia como medida de prevención ya que, en función de la ofuscación que se aplique al binario puede no contener de forma visible las cadenas de caracteres buscadas por estas reglas.

rule Night_Sky {
   strings:
      $s1 = "ransom" 
      $s2 = "tset123155465463213"
      $s3 = "!This program cannot be run in DOS mode."
      $s4 = "nightsky"
      $s5 = "MoveFileExW" 
      $s6 = "-----BEGIN PUBLIC KEY-----"
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and all of ($s*)
}
