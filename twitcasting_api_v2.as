#ifndef __TWITCASTING_APIV2__
#define __TWITCASTING_APIV2__

#include "hspinet.as"
#include "hspsock.as"
#include "simple_encryptor.as"

#define global TC_INIT_WITH_NETINIT 1

#define global TC_OK 1
#define global TC_ERROR_ACCESSTOKEN_NOT_SUPLIED 2
#define global TC_ERROR_NOT_INITIALIZED 3
#define global TC_ERROR_INTERNET 4
#define global TC_ERROR_ACCOUNT_OUT_OF_RANGE 5
#define global TC_ERROR_API 6
#define global TC_ERROR_UNKNOWN 99

#module twitcasting_api_v2
#define TC_CALLBACK_PORT 9338
#define TC_BASE_URI "https://apiv2.twitcasting.tv/"

#deffunc tc_init str _ci, str _cs, int _ni_flag
/*
tc_init client_id,client_secret,do_netinit(default=0, 1(TC_INIT_WITH_NETINIT) to enable)
*/

initialized=1
client_id=_ci
client_secret=_cs
access_token=""
if _ni_flag=TC_INIT_WITH_NETINIT:netinit@
rData=""
accessTokens=""
accessTokensNum=0
encryptor_init
return

#deffunc tc_userLogin local _act
/*
tc_userLogin
returns slot number, -1 on error
*/
if initialized=0:return -1
//set up a local http server to receive access token and access secret
sockmake@ 0,TC_CALLBACK_PORT
if stat!=0:{
dialog "ソケットの初期化に失敗しました。",,"Twitcasting API"
return
}
exec strf(TC_BASE_URI+"oauth2/authorize?client_id=%s&response_type=code&state=",client_id),16
errored=0
repeat
await 50
sockwait@ 0
s=stat
if s=0:break
if s>1:errored=1:break
loop
if errored:{
sockclose@ 0
dialog "データの大気中にエラーが発生しました。",,"Twitcasting API"
return -1
}
errored=0
repeat
await 50
sockcheck@ 0
s=stat
if s=0:break
if s>1:errored=1:break
loop
if errored=1:{
sockclose@ 0
dialog "データの受診中にエラーが発生しました。",,"Twitcasting API"
return -1
}
sdim rcv,8192
sockgetb@ rcv,0,8192,0
sdim response,2048
response="HTTP/1.1 200 OK\n"
response+="Content-Type: text/html;charset=shift-jis\n"
response+="Connection: Close\n\n"
response+="<!DOCTYPE html>\n"
response+="<html>\n"
if instr(rcv,0,"result=denied")!=-1:{//canceled
response+="<head><title>アカウントの連携失敗 - TCV</title>\n"
response+="<body>\n"
response+="<h1>接続拒否</h1>\n"
response+="<p>連携アプリの認証が拒否されたため、ツイキャスアカウントとTCVを接続することができませんでした。このウィンドウを閉じて、最初からやり直してください。</p>\n"
response+="</body></html>"
sockput@ response,0
sockclose@ 0
return -1
}//end canceled
//post the code to API again
code=strmid(rcv,11,instr(rcv,11," "))
neturl@ TC_BASE_URI+"oauth2/"
param=strf("code=%s&grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=http://localhost:%d/",code,client_id,client_secret,TC_CALLBACK_PORT)
netrequest_post@ "access_token",param
if tc_internal_receive()!=TC_OK:{//failure
errorstr=""
neterror@ errorstr
response+="<head><title>アカウントの連携失敗 - TCV</title>\n"
response+="<body>\n"
response+="<h1>接続失敗</h1>\n"
response+="<p>連携アプリの認証中にリクエストエラー("+errorstr+")が発生したため、ツイキャスアカウントとTCVを接続することができませんでした。このウィンドウを閉じて、最初からやり直してください。</p>\n"
response+="</body></html>"
sockput@ response,0
sockclose@ 0
return -1
}//end failure
netgetv@ rData
//parse token
s=instr(rData,0,"access_token")
if s=-1:{//unexpected
bsave "errorLog.txt",rData,strlen(rData)
response+="<head><title>アカウントの連携失敗 - TCV</title>\n"
response+="<body>\n"
response+="<h1>接続失敗</h1>\n"
response+="<p>連携アプリの認証中にリクエストエラー(原因不明)が発生したため、ツイキャスアカウントとTCVを接続することができませんでした。レスポンスの詳細については、TCVのフォルダに保存された errorLog.txt を参照してください。このウィンドウを閉じて、最初からやり直してください。</p>\n"
response+="</body></html>"
sockput@ response,0
sockclose@ 0
return -1
}//end failure
s+=15//access token starts here in index
_act=strmid(rData,s,instr(rData,s,"\""))
//return html
response+="<head><title>アカウントの連携完了 - TCV</title>\n"
response+="<body>\n"
response+="<h1>接続完了</h1>\n"
response+="<p>ツイキャスアカウントとTCVとの接続が正常に完了しました。このウィンドウを閉じてください。</p>\n"
response+="</body></html>"
sockput@ response,0
sockclose@ 0
notesel accessTokens
noteadd _act,accessTokensNum
accessTokensNum++
noteunsel
return accessTokensNum-1

#defcfunc tc_getNumberOfAccessTokens
return accessTokensNum

#deffunc tc_loadAccessTokens str _fname, local _s, local _tmp, local _tmp2, local _os
/*
tc_loadAccessTokens file_name
returns the number of loaded access tokens
remarks: use this function to load cached access tokens from a file.
*/
exist _fname
_s=strsize
if _s<=0:return 0
sdim _tmp,_s
bload _fname,_tmp
if encryptor_checkEncrypted(_tmp)==0:{
_os=0
encryptor_encrypt _tmp,_s,_tmp2,_os
bsave _fname,_tmp2,_os
sdim _tmp2,0
_s=_os
}
sdim _tmp,_s
bload _fname,_tmp
encryptor_decrypt _tmp,_s,accessTokens,_os
notesel accessTokens
accessTokensNum=notemax
noteunsel
return accessTokensNum

#deffunc tc_saveAccessTokens str _fname, local _o, local _os
/*
tc_saveAccessTokens file_to_save
returns the number of access tokens saved on success, -1 on failure
*/
encryptor_encrypt accessTokens,strlen(accessTokens),_o,_os
bsave _fname,_o,_os
return accessTokensNum

#deffunc tc_accessTokensUp int _slot, local _n1, local _n2
/*
tc_accessTokensUp num_to_move_up
returns 1 on success, 0 on failure
*/
if _slot=0:return 0
if _slot>=accessTokensNum:return 0
notesel accessTokens
noteget _n1,_slot
noteget _n2,_slot-1
noteadd _n2,_slot,1
noteadd _n1,_slot-1,1
noteunsel
return 1

#deffunc tc_accessTokensDown int _slot, local _n1, local _n2
/*
tc_accessTokensUp num_to_move_down
returns 1 on success, 0 on failure
*/
if _slot>=accessTokensNum-1:return 0
notesel accessTokens
noteget _n1,_slot
noteget _n2,_slot+1
noteadd _n2,_slot,1
noteadd _n1,_slot+1,1
noteunsel
return

#deffunc tc_accessTokenDelete int _slot
/*
tc_accessTokenDelete slot_to_delete
*/
if _slot>=accessTokensNum:return 0
notesel accessTokens
notedel _slot
noteunsel
return

/*
common API calling convention: tc_xx slot,outBuf(automatically initialized),input1,input2...
Always returns TC_OK or TC_ERROR_XX
*/

#defcfunc tc_call_getUserInfo int _slot, var _out, str _input1
/*input1: user name to get*/
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"users/",_input1)

#defcfunc tc_call_verifyCredentials int _slot, var _out
/*no input*/
return tc_internal_callAPI(_slot,_out,TC_BASE_URI,"verify_credentials")

/*"Get Live Thumbnail Image" is not implemented. Just let me know if you want it; I'm lazy!*/

#defcfunc tc_call_getMovieInfo int _slot, var _out, str _input1
/*input1: movie id to get */
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"movies/",_input1)

#defcfunc tc_call_getMoviesByUser int _slot, var _out, str _input1, int _input2, int _input3
/*input1: user name of which movies are retrieved. input 2: offset. input3: limit. */
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"users/"+_input1+"/","movies?offset="+_input2+"&limit="+_input3)

#defcfunc tc_call_getCurrentLive int _slot, var _out, str _input1
/*input1: User name of which current movie is retrieved. */
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"users/"+_input1+"/","current_live")

#defcfunc tc_call_getComments int _slot, var _out, str _input1, int _input2, int _input3, double _input4, local _slice
/*input1: movie ID of which comments are retrieved. Input 2: offset. Input3: limit. Input4: (optional) slice_id. */
_slice=strf("%.0f",_input4)
//dialog "slice="+_slice
if _input4=0.0:{
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"movies/"+_input1+"/","comments?offset="+_input2+"&limit="+_input3)
}else{
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"movies/"+_input1+"/","comments?offset="+_input2+"&limit="+_input3+"&slice_id="+_slice)
}

#defcfunc tc_call_postComment int _slot, var _out, str _input1, str _input2, str _input3, local comment_in_utf8, local _sns,local _st
/*input1: Movie ID to which the comment will be posted. Input2: comment body in SJIS(automatically UTF-8 converted by this function). input3: whether post to sns(none, reply or normal) */
_sns=_input3
switch _sns
case "none":
case "reply":
case "normal":
swbreak
default:
_sns="none"
swend
_st=_input2
cnvstoa _st,_st
nkfcnv@ comment_in_utf8,_st,"Sw"
return tc_internal_callPostAPI(_slot,_out,TC_BASE_URI+"movies/"+_input1+"/","comments","{\"comment\": \""+comment_in_utf8+"\", \"sns\": \""+_sns+"\"}")

#defcfunc tc_call_deleteComment int _slot, var _out, str _input1, str _input2
/*input1: Movie ID on which the comment is located. Input2: comment ID to delete. */
return tc_internal_callDeleteAPI(_slot,_out,TC_BASE_URI+"movies/"+_input1+"/comments/",_input2)



#defcfunc tc_call_getSupportingStatus int _slot, var _out, str _input1, str _input2
/*input1: Username to check if they are supporting target user. Input2: target user name. */
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"users/"+_input1+"/","supporting_status?target_user_id="+_input2)

/* "support user" is not implemented because hspinets doesn't support http put */

/* "unsupport user" is not implemented because hspinets doesn't support http put */

#defcfunc tc_call_supportingList int _slot, var _out, str _input1, int _input2, int _input3
/*input1: Username of which supporting list is retrieved. input2: offset. input3: limit.*/
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"users/"+_input1+"/","supporting?offset="+_input2+"&limit="+_input3)

#defcfunc tc_call_supporterList int _slot, var _out, str _input1, int _input2, int _input3, str _input4, local _srt
/*input1: Username of which supporters list is retrieved. input2: offset. input3: limit. input4: sorting algorithm (new or ranking, default: new) */
_srt=_input4
switch _srt
case "new":
case "ranking":
swbreak
default:
_srt="new"
swend
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"users/"+_input1+"/","supporters?offset="+_input2+"&limit="+_input3+"&sort="+_srt)

#defcfunc tc_call_getCategories int _slot, var _out, str _input1, local _lng
/* input1: language (ja or en, default: ja" */
_lng=_input1
switch _lng
case "ja":
case "en":
swbreak
default:
_lng="ja"
swend
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"categories","?lang="+_lng)

#defcfunc tc_call_searchUsers  int _slot, var _out, str _input1, str _input2, local _term_in_utf8, local _lng,local _st
/* input1: search term in SJIS(automatically utf-8 converted by this function). input2: language (ja or en, default: ja)*/
_lng=_input2
switch _lng
case "ja":
case "en":
swbreak
default:
_lng="ja"
swend
cnvstoa _st,_input1
nkfcnv@ _term_in_utf8,_st,"Sw"
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"search/","users?words="+_term_in_utf8+"&lang="+_lng)

#defcfunc tc_call_searchLives int _slot, var _out, str _input1, str _input2, int _input3, str _input4, local _term_in_utf8, local _lng,local _st
/* input1: search type(tag, word, category, new or recommend, must be specified). input2: context. input3: limit. input4: language (ja or en, default: ja)*/
_lng=_input2
switch _lng
case "ja":
case "en":
swbreak
default:
_lng="ja"
swend
cnvstoa _st,_input2
nkfcnv@ _term_in_utf8,_input2,"Sw"
return tc_internal_callAPI(_slot,_out,TC_BASE_URI+"search/","lives?type="+_input1+"&context="+_term_in_utf8+"&limit="+_input3+"&lang="+_lng)

/* Webhooks and streaming API's are not implemented. */

//helper functions
#defcfunc tc_id2categoryName str _i, str _term, local _p, local _in
/*
tc_id2categoryName categories_list_str,id_to_get_name 
the first parameter must be the result of tc_call_getCategoriesList
*/
_in=_i
_p=instr(_in,0,_term)
_p+=instr(_in,_p,"name")+7
return strmid(_in,_p,instr(_in,_p,"\""))

#defcfunc tc_getValue var _in, str _key, int _occurrence, local _cursor, local _fail, local _oc, local _buf, local _parsingType, local _i, local _p
/*
tc_getValue input_JSON,key_name, occurrence_count
Remarks: gets the value associated with the given key. Use this function after retrieving API call results. occurrence 1 means first, 2 means second. The occurrence is clipped to 1 when less than that. Arrays can be retrieved as well.
If the given key at the specified occurrence doesn't exist, return ""
*/
_oc=_occurrence
if _oc<=0:_oc=1
_fail=0
_cursor=0
_parsingType=0
repeat _oc
s=instr(_in,_cursor,"\""+_key+"\"")
if s=-1:_fail=1:break
_cursor+=s
_cursor+=strlen(_key)+3
switch peek(_in,_cursor)
case '"':_cursor++:swbreak//string
case '[':_cursor+=2:_parsingType=1:swbreak//array
default:_parsingType=2:swbreak//number or true/false
swend
loop
if _fail=1:return ""
if _parsingType!=2:{//normal parsing
_p=_cursor
//\" shouldn't be considered as end of string
repeat
_p+=instr(_in,_p,"\"")
if peek(_in,_p-1)!=0x5c:break
_p++//one char to the right, or it'll cause infinite loop
loop
_buf=strmid(_in,_cursor,_p-_cursor)
strrep _buf,"\\\"","\""
}else{//parsing for numbers / true falses
_buf=strmid(_in,_cursor,instr(_in,_cursor,","))
}
if _buf="null":if peek(_in,_cursor-1)!='"': _buf=""
if _parsingType=1:{//array
_cursor+=strlen(_buf)+1
repeat
if peek(_in,_cursor)=',':{
_cursor+=2
_i=instr(_in,_cursor,"\"")
_buf+=","+strmid(_in,_cursor,_i)
_cursor+=_i+1
}else{
break
}
loop
}
return _buf

#defcfunc tc_get_errorstring int _error, local _errorstr
_errorstr=""
switch _error
case TC_OK:
_errorstr="正常に終了しました。"
swbreak
case TC_ERROR_NOT_INITIALIZED:
_errorstr="モジュールの初期化が正しく行われていません。"
swbreak
case TC_ERROR_ACCESSTOKEN_NOT_SUPLIED:
_errorstr="access tokenの設定が完了していません。"
swbreak
case TC_ERROR_INTERNET:
_errorstr="通信エラーが発生しました。"
swbreak
case TC_ERROR_ACCOUNT_OUT_OF_RANGE
_errorstr="指定されたスロットにアカウントがありません。"
swbreak
case TC_ERROR_API
_errorstr="ツイキャスAPI側のエラーです。"
swbreak
default:
_errorstr="不明なエラーです。"
swend
return _errorstr

#defcfunc tc_internal_callAPI int _slot, var _out, str _head, str _body, local _token
if _slot>=accessTokensNum: return TC_ERROR_ACCOUNT_OUT_OF_RANGE
notesel accessTokens
noteget _token,_slot
noteunsel
neturl@ _head
netheader@ ""
netheader@ strf("Accept: application/json\nX-Api-Version: 2.0\nAuthorization: Bearer %s\n\n",_token)
netrequest_get@ _body
ret=tc_internal_receive()
if ret!=TC_OK:return ret
netgetv@ out_tmp
nkfcnv@ _out,out_tmp,"Ws"
_out=cnvatos(_out)
sdim out_tmp,0
return tc_internal_apiErrorCheck(_out)

#defcfunc tc_internal_callDeleteAPI int _slot, var _out, str _head, str _body, local _token
if _slot>=accessTokensNum: return TC_ERROR_ACCOUNT_OUT_OF_RANGE
notesel accessTokens
noteget _token,_slot
noteunsel
neturl@ _head
netheader@ ""
netheader@ strf("Accept: application/json\nX-Api-Version: 2.0\nAuthorization: Bearer %s\n\n",_token)
netrequest_delete@ _body
ret=tc_internal_receive()
if ret!=TC_OK:return ret
netgetv@ out_tmp
nkfcnv@ _out,out_tmp,"W"
_out=cnvatos(_out)
sdim out_tmp,0
return tc_internal_apiErrorCheck(_out)

#defcfunc tc_internal_callPostAPI int _slot, var _out, str _head, str _body, str _param, local _p
_p=_param
if _slot>=accessTokensNum: return TC_ERROR_ACCOUNT_OUT_OF_RANGE
notesel accessTokens
noteget _token,_slot
noteunsel
neturl@ _head
netheader@ ""
netheader@ strf("Accept: application/json\nX-Api-Version: 2.0\nAuthorization: Bearer %s\n\n",_token)
netrequest_post@ _body,_p
ret=tc_internal_receive()
if ret!=TC_OK:return ret
netgetv@ out_tmp
nkfcnv@ _out,out_tmp,"Ws"
_out=cnvatos(_out)
sdim out_tmp,0
return tc_internal_apiErrorCheck(_out)

#defcfunc tc_internal_apiErrorCheck var _out, local _code, local _string
if instr(_out,0,"{\"error\":")!=-1:{
_code=tc_getValue(_out,"code",1)
if _code="404":return TC_ERROR_API

switch _code
	case "1000"
		_string="アクセストークンが無効なため、通信に失敗しました。\n以下のような原因が考えられます。\n"
		_string+="　・TCVでのアカウント登録から180日が経過した\n"
		_string+="　・アカウントが削除された\n"
		_string+="　・TCVとアカウントの連携が解除された\n"
		_string+="　・システムファイルaccounts.datが破損した\n"
		_string+="\n\nお手数ですが、TCV起動直後の画面よりアカウント設定に入り、いったんアカウントを削除してから再度追加しなおしてください。"
		swbreak
	case "2001"
		_string="TCVによるツイキャスへのアクセスが拒否されています。\nこのメッセージを添えて、作者に支給ご連絡ください。"
		swbreak
	case "2003"
		_string="連続で同じ内容のコメントを送信する事はできません。"
		swbreak
	case "2006"
		_string="この機能を利用するためには、事前にEメールアドレスの認証を行う必要があります。"
		swbreak
	default
		_string="ツイキャスAPIがエラーを返しました。"
	swend

if _code!="404":dialog strf("%s\n\n %s(%d)",_string,tc_getValue(_out,"message",1),_code),,"Twitcasting API"
return TC_ERROR_API
}
return TC_OK


#defcfunc tc_internal_receive local irs, local irr
irs=0
irr=TC_OK
repeat
netexec@ irs
if irs<0:irr=TC_ERROR_INTERNET:break
if irs>0:break
await 1
loop
return irr


#global

#endif

#if 0
a="\"name\":\"石野　一郎@\\\"だれかの偽アカ\\\"\",\"image\":\"http"
dialog tc_getValue(a,"name")
end
#endif