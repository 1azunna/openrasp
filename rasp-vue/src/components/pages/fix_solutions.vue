<template>
    <div class="event-detail">
        <div v-if="data.attack_type == 'sql'">
            SQL injection is mostly caused by statement splicing. Please check whether there is parameter splicing in the code. When conditions permit, try to use prepare query to fix vulnerabilities.
        </div>

        <div v-if="data.attack_type =='sql_exception'">
            Check whether the abnormal SQL statement comes from normal operation, if not, check whether the application has vulnerabilities.
        </div>

        <div v-if="data.attack_type =='directory'">
            Usually applications will not read sensitive directories, please confirm with the line of business whether this is a normal behavior. If not, please check the server based on the stack to see if there is a webshell backdoor.
        </div>

        <div v-if="data.attack_type =='readFile'">
            Usually the application will not read sensitive files, please confirm with the line of business whether this is a normal behavior. If not, please check the server based on the stack to see if there is a webshell backdoor.
        </div>

        <div v-if="data.attack_type =='deleteFile'">
            Filter or verify the incoming file path.
        </div>

        <div v-if="data.attack_type =='writeFile'">
            Filter the file names to be deleted, such as restricting directories, etc., to avoid damage to the system.
        </div>

        <div v-if="data.attack_type =='include'">
            Please check whether the file to be included is normal, otherwise it means that there is a file inclusion vulnerability on the server.
        </div>

        <div v-if="data.attack_type =='webdav'">
            Please check whether the MOVE/PUT operation is enabled on the server. Attackers can use a special HTTP method to upload the webshell backdoor. This algorithm has no false positives.
        </div>

        <div v-if="data.attack_type =='fileUpload'">
            When the server allows users to upload files without filtering extensions, it may cause arbitrary file upload vulnerabilities. The fix is ​​to use a whitelist of extensions, such as allowing only suffixes such as txt/png/jpg. This algorithm usually has no false positives.
        </div>

        <div v-if="data.attack_type =='rename'">
            When the server has vulnerabilities, the attacker can rename the unexecutable txt/rar file name to php/jsp/.. and other executable script files. This algorithm will falsely report under some PHP frameworks.
        </div>

        <div v-if="data.attack_type =='command'">
            If the execution of this command is not a normal business requirement, it is most likely an operation performed by the webshell backdoor, or a command executed by an attacker using a vulnerability.
        </div>

        <div v-if="data.attack_type =='xxe'">
            Check whether the business code directly processes the xml input by the user and allows any external entities to be loaded. If allowed, there may be an xxe vulnerability.
            After v1.1, we will add the XXE code security switch, which will automatically prevent you from loading xml entities and automatically fix vulnerabilities.
        </div>

        <div v-if="data.attack_type =='ognl'">
            Try to upgrade struts to the new version, or promote business transformation, using other development frameworks. At Baidu, we have banned business lines from using the struts framework.
        </div>

        <div v-if="data.attack_type =='deserialization'">
            Check whether the system has known deserialization vulnerabilities, and upgrade the software or framework to the latest version.
        </div>

        <div v-if="data.attack_type =='link'">
            If this link operation is not a normal business requirement, it is most likely an operation performed by the webshell backdoor, for example, to bypass EDR detection.
        </div>

        <div v-if="data.attack_type =='ssrf' || data.attack_type =='ssrfRedirect'">
            Check the business code to see if it is possible to directly initiate a request to the intranet URL specified by the user.
        </div>

        <!-- The following is php native -->

        <div v-if="data.attack_type =='webshell_eval'">
            Check whether there is a Chinese kitchen knife backdoor on the server. The backdoor may also exist in the business code. Please refer to the application stack for details.
        </div>

        <div v-if="data.attack_type =='webshell_command'">
            Check whether there is a webshell backdoor or a command execution point that can be exploited on the server. This algorithm has no false positives.
        </div>

        <div v-if="data.attack_type =='webshell_file_put_contents'">
            Check whether there is a webshell backdoor on the server, or a backdoor upload point that can be utilized, this algorithm has no false positives.
        </div>
        
        <div v-if="data.attack_type =='webshell_callable'">
            Check whether there is a webshell backdoor on the server, that is, use call_user_func/array_walk/.. to call system/exec/... and other functions. This algorithm has no false positives.
        </div>

        <div v-if="data.attack_type =='webshell_ld_preload'">
            Check whether there is a webshell backdoor on the server, that is, use putenv + LD_PRELOAD + mail to execute any command backdoor.
        </div>

        <div v-if="data.attack_type =='xss_userinput' || data.attack_type =='xss_echo'">
            Check whether the application directly outputs the parameters passed in by the user, consider using ESAPI to escape.
        </div>

        <div v-if="data.attack_type =='eval'">
            Avoid using eval/assert functions, or check whether the target file is a backdoor program.
        </div>

        <div v-if="data.attack_type =='loadLibrary'">
            Check whether the target file is a backdoor.
        </div>

        <div v-if="data.attack_type =='response'">
            Encode sensitive data in the response to avoid displaying plaintext data.        
        </div> 

    </div>

</template>

<script>

export default {
    name: 'fix_solutions',
    data: function () {
        return {
            data: {
                attack_params: {}
            }
        }
    },
    methods: {
        setData: function (data) {
            this.data = data
        }
    }
}
</script>

