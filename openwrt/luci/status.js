'use strict';
'require view';
'require rpc';
'require poll';
'require ui';

var statusCall = rpc.declare({ object: 'luci.campusvpn', method: 'status' });
var loginCall = rpc.declare({ object: 'luci.campusvpn', method: 'login', params: ['username', 'password'] });
var disconnectCall = rpc.declare({ object: 'luci.campusvpn', method: 'disconnect' });
var reconnectCall = rpc.declare({ object: 'luci.campusvpn', method: 'reconnect' });
var labels = { idle: '未连接', connecting: '正在连接', connected: '已连接', stopping: '正在断开', failed: '连接失败', unavailable: '服务不可用' };
var autoLabels = { disabled: '未配置', paused: '已暂停', trying: '正在连接', connected: '已启用', offline: '网络不可用，等待恢复', 'retry-limit': '已达重试上限，请手动恢复', 'authentication-paused': '认证失败，请检查账号或学校验证', 'cleanup-required': '网络清理异常，请检查', error: '配置读写失败' };
return view.extend({
 load: function() { return statusCall().catch(function(){ return {state:'unavailable'}; }); },
 render: function(initial) {
  var badge=E('strong',{},'正在读取'), since=E('span',{},'—'), autos=E('span',{},'—'), event=E('div',{},'正在读取状态'), user=E('input',{type:'text',autocomplete:'username',placeholder:'校园账号'}), pass=E('input',{type:'password',autocomplete:'current-password',placeholder:'校园密码'});
  var connect=E('button',{'class':'btn cbi-button-action'},'保存并连接'), reconnect=E('button',{'class':'btn'},'使用已保存账号连接'), disconnect=E('button',{'class':'btn cbi-button-negative'},'断开并暂停自动登录');
  var current=initial||{}, ts=0;
  function duration() { if(!ts || current.state!=='connected') { since.textContent='—'; return; } var n=Math.max(0,Math.floor((Date.now()-ts)/1000)); since.textContent=Math.floor(n/3600)+' 小时 '+Math.floor(n%3600/60)+' 分 '+n%60+' 秒'; }
  function display(x) { current=x||{};badge.textContent=labels[current.state]||'未知状态';autos.textContent=autoLabels[current.auto_state]||current.auto_state||'未配置';ts=current.connected_since?Date.parse(current.connected_since):0;duration();event.textContent=current.message||('最近状态：'+(current.stage||current.last_event||'等待操作'));connect.disabled=current.state==='connected'||current.state==='connecting'||current.state==='stopping';reconnect.disabled=connect.disabled;disconnect.disabled=current.state==='stopping'; }
  function notify(x) {if(!x||!x.ok)ui.addNotification(null,E('p',{},(x&&x.message)||'操作未成功，请查看状态'), 'error');display(x);}
  connect.addEventListener('click',function(){ if(location.protocol!=='https:'){ui.addNotification(null,E('p',{},'为保护密码，请使用 HTTPS 打开路由器后台后再登录。'),'error');return;}if(!user.value||!pass.value){ui.addNotification(null,E('p',{},'请输入校园账号和密码。'),'error');return;}var u=user.value,p=pass.value;pass.value='';loginCall(u,p).then(notify).catch(function(){ui.addNotification(null,E('p',{},'请求失败，请检查服务。'),'error')});p=''; });
  reconnect.addEventListener('click',function(){reconnectCall().then(notify).catch(function(){ui.addNotification(null,E('p',{},'请求失败'),'error')});});
  disconnect.addEventListener('click',function(){disconnect.disabled=true;disconnectCall().then(notify).catch(function(){ui.addNotification(null,E('p',{},'断开请求失败'),'error');disconnect.disabled=false});});
  var pane=E('div',{'class':'cbi-map'},[E('h2',{},'智慧安农VPN'),E('div',{'class':'cbi-section'},[E('h3',{},'连接状态'),E('p',{},[badge]),E('p',{},'输入账号后保存并连接；密码仅保存在路由器受限文件中。'),E('div',{'class':'cbi-value'},[E('label',{'class':'cbi-value-title'},'校园账号'),E('div',{'class':'cbi-value-field'},[user])]),E('div',{'class':'cbi-value'},[E('label',{'class':'cbi-value-title'},'校园密码'),E('div',{'class':'cbi-value-field'},[pass])]),E('p',{},[connect,' ',reconnect,' ',disconnect])]),E('div',{'class':'cbi-section'},[E('h3',{},'运行信息'),E('p',{},['连接时长：',since]),E('p',{},['自动连接：',autos]),E('p',{},[event]),E('p',{'class':'description'},'断网时暂停登录，网络恢复后有限重试；认证失败或达到上限时等待手动处理。')])]);
  display(current);poll.add(function(){return statusCall().then(display).catch(function(){display({state:'unavailable'});});},5);window.setInterval(duration,1000);return pane;
 },handleSave:null,handleSaveApply:null,handleReset:null
});
