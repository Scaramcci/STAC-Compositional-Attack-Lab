import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Presentation, PresentationFile } from '@oai/artifact-tool';

process.env.RUNTIME_NODE_MODULES='/home/scarramcci/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules';
process.env.RUNTIME_NODE='/home/scarramcci/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node';
const workspaceDir='/home/scarramcci/Project/STAC-Compositional-Attack-Lab';
const buildDir=path.join(workspaceDir,'.codex-ppt-build');
const outputDir=path.join(workspaceDir,'ppt-output');
const SKILL_DIR='/home/scarramcci/.codex/plugins/cache/openai-primary-runtime/presentations/26.909.61513/skills/presentations';
const RUNTIME_PYTHON='/usr/bin/python3';
const finalPath=path.join(outputDir,'STAC_Primitive_Research_Update_CUHK.pptx');
const logo=await fs.readFile(path.join(buildDir,'CUHK_Logo.png'));

const P={purple:'#6F2472', deep:'#4D174F', gold:'#E5AE2B', pale:'#F7E9BB', ink:'#24212A', gray:'#706A73', soft:'#F4F2F5', white:'#FFFFFF', lightPurple:'#F2EAF3', green:'#287A63'};
const FONT='Noto Sans CJK SC';
const presentation=Presentation.create({slideSize:{width:1280,height:720}});

function shape(slide, geometry, pos, fill='none', line='none', radius=0){
  return slide.shapes.add({geometry,position:pos,fill,line:line==='none'?{fill:'none',width:0}:line,...(radius?{borderRadius:radius}:{})});
}
function textBox(slide, text, pos, opts={}){
  const s=shape(slide,'textbox',pos,opts.fill??'none',opts.line??'none',opts.radius??0);
  s.text=text;
  s.text.style={typeface:opts.font??FONT,fontSize:opts.size??24,bold:opts.bold??false,color:opts.color??P.ink,autoFit:'shrinkText',alignment:opts.align??'left',verticalAlignment:opts.valign??'middle'};
  return s;
}
function contentSlide(title, section, notes){
  const slide=presentation.slides.add();
  slide.background.fill=P.white;
  shape(slide,'rect',{left:0,top:0,width:1280,height:24},P.deep);
  const labels=['Primitive','代码','进展'];
  const xs=[25,590,1110];
  labels.forEach((l,i)=>textBox(slide,l,{left:xs[i],top:0,width:140,height:22},{size:11,color:i===section?P.white:'#DCCADF',bold:i===section}));
  shape(slide,'rect',{left:0,top:24,width:1280,height:64},P.purple);
  textBox(slide,title,{left:34,top:26,width:1150,height:58},{size:29,color:P.white,bold:true});
  shape(slide,'rect',{left:1238,top:38,width:7,height:27},P.gold);
  shape(slide,'rect',{left:0,top:688,width:1280,height:32},P.purple);
  textBox(slide,'STAC Compositional Attack Lab',{left:28,top:691,width:620,height:24},{size:12,color:P.white});
  textBox(slide,`${presentation.slides.items.length}/16`,{left:1140,top:691,width:100,height:24},{size:12,color:P.gold,bold:true,align:'right'});
  slide.speakerNotes.textFrame.setText(notes);
  return slide;
}
function addBulletList(slide, items, pos, opts={}){
  const lineH=opts.lineH??52;
  items.forEach((item,i)=>{
    shape(slide,'ellipse',{left:pos.left,top:pos.top+i*lineH+12,width:13,height:13},i===opts.accentIndex?P.gold:P.purple);
    textBox(slide,item,{left:pos.left+28,top:pos.top+i*lineH,width:pos.width-28,height:lineH-2},{size:opts.size??23,color:opts.color??P.ink,bold:opts.bold??false});
  });
}
function labelBox(slide,title,body,pos,accent=P.purple){
  shape(slide,'roundRect',pos,P.soft,{style:'solid',fill:'#D9D2DB',width:1},12);
  shape(slide,'rect',{left:pos.left,top:pos.top,width:8,height:pos.height},accent);
  textBox(slide,title,{left:pos.left+24,top:pos.top+13,width:pos.width-40,height:34},{size:22,color:accent,bold:true});
  textBox(slide,body,{left:pos.left+24,top:pos.top+54,width:pos.width-40,height:pos.height-65},{size:18,color:P.ink});
}
function stepBox(slide,label,x,y,w=190,h=72,fill=P.soft){
  const s=shape(slide,'roundRect',{left:x,top:y,width:w,height:h},fill,{style:'solid',fill:P.purple,width:2},14);
  textBox(slide,label,{left:x+10,top:y+8,width:w-20,height:h-16},{size:20,color:P.deep,bold:true,align:'center'});
  return s;
}
function connect(slide,a,b,from='right',to='left'){
  slide.shapes.connect(a,b,{kind:'straight',fromSide:from,toSide:to,line:{style:'solid',fill:P.gold,width:4},tail:{type:'triangle',width:'sm',length:'sm'}});
}
function codeBlock(slide, txt, pos){
  shape(slide,'roundRect',pos,'#FBF9FC',{style:'solid',fill:'#CDBDCF',width:1},10);
  textBox(slide,txt,{left:pos.left+18,top:pos.top+10,width:pos.width-36,height:pos.height-20},{font:'DejaVu Sans Mono',size:17,color:P.deep});
}

// 1 Cover
{
 const slide=presentation.slides.add(); slide.background.fill=P.purple;
 shape(slide,'rect',{left:910,top:0,width:370,height:720},P.gold);
 shape(slide,'rect',{left:890,top:0,width:20,height:720},P.deep);
 textBox(slide,'Agent信息流分析与组合攻击',{left:78,top:128,width:760,height:94},{size:38,color:P.white,bold:true});
 textBox(slide,'Primitive设计、代码实现与工作进展',{left:80,top:228,width:720,height:54},{size:24,color:P.pale,bold:true});
 textBox(slide,'STAC Compositional Attack Lab',{left:80,top:362,width:650,height:40},{size:20,color:P.white});
 textBox(slide,'The Chinese University of Hong Kong',{left:80,top:408,width:650,height:36},{size:17,color:P.white});
 textBox(slide,'2026年9月',{left:80,top:470,width:300,height:34},{size:18,color:P.pale});
 slide.images.add({blob:logo,contentType:'image/png',alt:'CUHK logo',fit:'contain',position:{left:990,top:58,width:210,height:180}});
 textBox(slide,'The Chinese University\nof Hong Kong',{left:958,top:592,width:260,height:60},{size:16,color:P.deep,align:'center'});
 slide.speakerNotes.textFrame.setText('开场：本次汇报介绍信息流Primitive、当前代码和下一步工作。\n来源：docs/基于文献的Primitive重构论证.md；docs/PROJECT_STRUCTURE_ZH.md。');
}

// 2
{
 const s=contentSlide('汇报内容',0,'用三句话介绍汇报结构。代码部分只做导航，随后切换VS Code。');
 labelBox(s,'Primitive表示信息流','三个底层操作与依赖关系',{left:70,top:155,width:350,height:250},P.purple);
 labelBox(s,'当前代码展示','核心目录与分析流程',{left:465,top:155,width:350,height:250},P.deep);
 labelBox(s,'未来工作和论文启发','当前困难与后续方向',{left:860,top:155,width:350,height:250},P.gold);
 textBox(s,'Primitive  ·  Code  ·  Future Work',{left:180,top:485,width:920,height:62},{size:25,color:P.purple,bold:true,align:'center'});
}

// 3
{
 const s=contentSlide('研究思路',0,'第一阶段分析交互轨迹并生成信息流图。第二阶段利用信息流辅助攻击。当前主要完成信息流表示与分析。\n来源：docs/论文阅读后关于idea的思考.md。');
 const labs=['SafeClawArena\n交互轨迹','信息流分析','信息流图','攻击规划','正式攻击'];
 const boxes=labs.map((x,i)=>stepBox(s,x,45+i*245,218,190,88,i<3?P.lightPurple:P.soft));
 for(let i=0;i<boxes.length-1;i++) connect(s,boxes[i],boxes[i+1]);
 textBox(s,'当前重点',{left:245,top:380,width:450,height:44},{size:20,color:P.purple,bold:true,align:'center'});
 shape(s,'line',{left:130,top:432,width:610,height:0},'none',{style:'solid',fill:P.purple,width:4});
 textBox(s,'信息流表示与分析',{left:180,top:448,width:500,height:46},{size:24,color:P.deep,bold:true,align:'center'});
 textBox(s,'待进一步明确',{left:810,top:380,width:300,height:44},{size:20,color:P.gray,bold:true,align:'center'});
 textBox(s,'图如何帮助攻击',{left:785,top:448,width:350,height:46},{size:24,color:P.ink,bold:true,align:'center'});
}

// 4
{
 const s=contentSlide('原有Primitive',0,'原有九项词表保留了有用的攻击叙述，但混合了来源、用途、资源和复合流程。\n来源：docs/基于文献的Primitive重构论证.md，第2节。');
 const words=['Ingest','Adopt','Persist','Recall','Select','Bind','Act','Record','Recover'];
 words.forEach((w,i)=>{
   const x=90+(i%3)*250, y=140+Math.floor(i/3)*90;
   shape(s,'roundRect',{left:x,top:y,width:200,height:60},i%2?P.soft:P.lightPurple,{style:'solid',fill:'#C9B4CB',width:1},12);
   textBox(s,w,{left:x,top:y+5,width:200,height:50},{size:21,color:P.deep,bold:true,align:'center'});
 });
 labelBox(s,'分类标准不同','来源、用途和资源类型混在一起',{left:850,top:138,width:350,height:110},P.purple);
 labelBox(s,'抽象粒度不同','单个操作和复合流程混在一起',{left:850,top:268,width:350,height:110},P.deep);
 labelBox(s,'观察能力不同','部分语义无法从日志直接读取',{left:850,top:398,width:350,height:110},P.gold);
 textBox(s,'底层表示需要统一的操作接口',{left:120,top:500,width:650,height:58},{size:25,color:P.purple,bold:true,align:'center'});
}

// 5
{
 const s=contentSlide('三个Primitive',0,'三类Primitive分别处理信息交付、信息产生和资源状态生效。它们还需要对象、依赖、版本和证据。\n来源：docs/基于文献的Primitive重构论证.md，第1、5节。');
 const cols=[
  ['TRANSFER','交付已有对象','消息传递\n工具返回\nmemory读取'],
  ['DERIVE','根据输入产生输出','摘要\n计划\n参数绑定'],
  ['UPDATE','改变资源状态','memory写入\n文件修改\n权限变化']
 ];
 cols.forEach((c,i)=>{
   const x=75+i*400;
   shape(s,'roundRect',{left:x,top:145,width:340,height:350},i===2?P.pale:P.soft,{style:'solid',fill:i===2?P.gold:P.purple,width:2},16);
   textBox(s,c[0],{left:x+20,top:170,width:300,height:60},{font:'DejaVu Sans',size:29,color:P.deep,bold:true,align:'center'});
   textBox(s,c[1],{left:x+25,top:245,width:290,height:48},{size:23,color:P.purple,bold:true,align:'center'});
   shape(s,'line',{left:x+45,top:310,width:250,height:0},'none',{style:'solid',fill:'#C9B4CB',width:2});
   textBox(s,c[2],{left:x+45,top:330,width:250,height:125},{size:20,color:P.ink,align:'center'});
 });
 textBox(s,'信息交付',{left:135,top:530,width:220,height:40},{size:20,color:P.purple,bold:true,align:'center'});
 textBox(s,'信息产生',{left:535,top:530,width:220,height:40},{size:20,color:P.purple,bold:true,align:'center'});
 textBox(s,'状态生效',{left:935,top:530,width:220,height:40},{size:20,color:P.deep,bold:true,align:'center'});
}

// 6
{
 const s=contentSlide('TRANSFER',0,'TRANSFER表示已有对象进入新的执行域。成功交付不代表接收者理解、相信或服从。\n来源：docs/基于文献的Primitive重构论证.md，第5.1节。');
 codeBlock(s,'TRANSFER(\n  source,\n  destination,\n  artifact,\n  channel,\n  delivery_id\n)',{left:75,top:140,width:440,height:390});
 addBulletList(s,['对象已经存在','进入新的执行域','对象身份保持不变','记录来源与交付通道','交付不等于理解或采纳'],{left:610,top:145,width:540},{size:23,lineH:68});
 textBox(s,'用户消息 → Agent上下文    工具结果 → Agent上下文',{left:145,top:574,width:990,height:42},{size:21,color:P.deep,bold:true,align:'center'});
}

// 7
{
 const s=contentSlide('DERIVE',0,'DERIVE表示局部处理产生新对象。没有中间证据时，一次模型调用可以保留为一个多输入、多输出效果。\n来源：docs/基于文献的Primitive重构论证.md，第5.2、9.4节。');
 codeBlock(s,'DERIVE(\n  executor,\n  inputs,\n  outputs,\n  operation,\n  invocation_id\n)',{left:75,top:140,width:440,height:390});
 addBulletList(s,['根据输入产生新对象','支持多个输入','支持多个输出','不要求语义等价','不恢复隐藏推理'],{left:610,top:145,width:540},{size:23,lineH:68});
 textBox(s,'两个文件 → 综合摘要    任务描述 → 执行计划',{left:150,top:574,width:980,height:42},{size:21,color:P.deep,bold:true,align:'center'});
}

// 8
{
 const s=contentSlide('UPDATE',0,'UPDATE表示有独立身份的资源状态已经生效变化。写入请求和工具成功声明都不能替代提交证据。\n来源：docs/基于文献的Primitive重构论证.md，第5.3节。');
 codeBlock(s,'UPDATE(\n  actor,\n  resource,\n  old_version,\n  new_version,\n  commit_id\n)',{left:75,top:140,width:440,height:390});
 addBulletList(s,['资源具有稳定身份','更新前后版本不同','新状态已经生效','请求写入不等于完成','成功声明不等于状态变化'],{left:610,top:145,width:540},{size:23,lineH:68});
 textBox(s,'memory v0 → v1    file v2 → v3    permission v0 → v1',{left:130,top:574,width:1020,height:42},{size:21,color:P.deep,bold:true,align:'center'});
}

// 9
{
 const s=contentSlide('依赖与控制',0,'Primitive描述发生的效果，依赖关系解释效果之间的联系。旧CONTROL中的控制影响由control_dep保留。\n来源：docs/基于文献的Primitive重构论证.md，第6节。');
 const relations=[['data_dep','输出使用某个输入'],['control_dep','输入影响操作是否发生'],['read_from','读取指定资源版本'],['happens_before','可观察的先后顺序']];
 relations.forEach((r,i)=>labelBox(s,r[0],r[1],{left:80+(i%2)*590,top:135+Math.floor(i/2)*145,width:520,height:112},i===1?P.gold:P.purple));
 shape(s,'roundRect',{left:145,top:465,width:990,height:95},P.pale,{style:'solid',fill:P.gold,width:1},12);
 textBox(s,'时间相邻不能证明数据依赖\n实际控制状态变化才记录为 UPDATE',{left:185,top:478,width:910,height:68},{size:24,color:P.deep,bold:true,align:'center'});
}

// 10
{
 const s=contentSlide('跨会话传播',0,'跨会话传播由UPDATE、版本读取和后续DERIVE组成。需要实际会话身份、持久范围、版本和后续使用证据。\n来源：docs/基于文献的Primitive重构论证.md，第8.3节；docs/PROJECT_STRUCTURE_ZH.md，第2、7节。');
 textBox(s,'Session A',{left:95,top:125,width:450,height:40},{size:23,color:P.purple,bold:true,align:'center'});
 textBox(s,'Session B',{left:735,top:125,width:450,height:40},{size:23,color:P.purple,bold:true,align:'center'});
 const a1=stepBox(s,'用户消息',105,190,180,65), a2=stepBox(s,'Agent上下文',365,190,180,65), a3=stepBox(s,'memory v0 → v1',235,335,220,72,P.pale);
 connect(s,a1,a2); connect(s,a2,a3,'bottom','top');
 textBox(s,'TRANSFER',{left:275,top:185,width:100,height:28},{font:'DejaVu Sans',size:13,color:P.gray,align:'center'});
 textBox(s,'DERIVE + UPDATE',{left:387,top:277,width:170,height:28},{font:'DejaVu Sans',size:13,color:P.gray,align:'center'});
 const b1=stepBox(s,'memory v1',745,190,180,65), b2=stepBox(s,'Agent上下文',1005,190,180,65), b3=stepBox(s,'回答或工具决策',875,335,220,72,P.lightPurple);
 connect(s,b1,b2); connect(s,b2,b3,'bottom','top');
 textBox(s,'TRANSFER',{left:915,top:185,width:100,height:28},{font:'DejaVu Sans',size:13,color:P.gray,align:'center'});
 textBox(s,'DERIVE',{left:1035,top:277,width:100,height:28},{font:'DejaVu Sans',size:13,color:P.gray,align:'center'});
 shape(s,'line',{left:455,top:372,width:420,height:0},'none',{style:'dash',fill:P.gold,width:4});
 textBox(s,'read_from + session boundary',{left:510,top:378,width:320,height:28},{font:'DejaVu Sans',size:14,color:P.deep,bold:true,align:'center'});
 addBulletList(s,['实际会话身份','持久资源范围','写入与读取版本','读取内容的后续使用'],{left:205,top:505,width:900},{size:18,lineH:36});
}

// 11
{
 const s=contentSlide('适用范围',0,'结论限定在固定观察范围和对象粒度内。三类接口不可简单互相替代，但不构成普适最小性定理。\n来源：docs/基于文献的Primitive重构论证.md，第9、12、13节。');
 labelBox(s,'能够表达','已记录的交付、输出、资源变化、依赖与版本',{left:90,top:145,width:500,height:185},P.purple);
 labelBox(s,'能够比较','不同操作接口的事实保留与重复计数',{left:690,top:145,width:500,height:185},P.deep);
 labelBox(s,'需要固定','观察范围、对象粒度、资源语义和证据来源',{left:90,top:365,width:500,height:185},P.gold);
 labelBox(s,'不能声称','唯一分解、普适最小基和自动真实重放',{left:690,top:365,width:500,height:185},P.gold);
}

// 12
{
 const s=contentSlide('代码结构',1,'本页只做VS Code导航。重点展示v3数据模型、投影、验证和离线分析入口。\n来源：docs/PROJECT_STRUCTURE_ZH.md。');
 codeBlock(s,'src/stac_attack_lab/\n├── flow/            v3数据模型\n├── interactions/    轨迹与信息流图\n├── extraction/      图切片\n├── verification/    依赖验证\n├── execution/       分析流程\n├── environments/    SafeClaw环境\n└── reporting/       结果报告',{left:70,top:125,width:650,height:450});
 labelBox(s,'VS Code展示','flow/models.py\ninteractions/flow_v3.py\nverification/flow_v3.py\nexecution/flow_reanalysis.py',{left:790,top:155,width:400,height:320},P.purple);
 textBox(s,'PPT讲结构，IDE讲实现',{left:800,top:515,width:380,height:42},{size:22,color:P.deep,bold:true,align:'center'});
}

// 13
{
 const s=contentSlide('分析流程',1,'轨迹先进入统一规范化表示，再投影成Effect Graph。Verifier独立裁决依赖，Slice保留与目标相关的结构。\n来源：docs/PROJECT_STRUCTURE_ZH.md，第6至8节。');
 const labs=['交互事件','规范化轨迹','Effect Graph','依赖验证','图切片','分析结果'];
 const boxes=labs.map((x,i)=>stepBox(s,x,45+i*202,225,160,78,i===2?P.pale:P.soft));
 for(let i=0;i<boxes.length-1;i++) connect(s,boxes[i],boxes[i+1]);
 textBox(s,'Projector提出claim',{left:400,top:355,width:280,height:44},{size:21,color:P.purple,bold:true,align:'center'});
 textBox(s,'Verifier独立裁决',{left:655,top:420,width:280,height:44},{size:21,color:P.deep,bold:true,align:'center'});
 textBox(s,'未观察内容保留为 unknown',{left:405,top:500,width:470,height:48},{size:23,color:P.gray,bold:true,align:'center'});
}

// 14
{
 const s=contentSlide('当前进展',2,'这一页只区分当前实现和后续工作，不把离线工程验证描述成真实实验结果。\n来源：docs/PROJECT_STRUCTURE_ZH.md，第18节；docs/IMPLEMENTATION_PROGRESS.md顶部。');
 labelBox(s,'目前已经完成','Primitive v3数据结构\nEffect Graph与多效果投影\n依赖验证与图切片\n跨会话版本关系\n正常交互轨迹分析\nSafeClaw环境适配',{left:75,top:130,width:530,height:430},P.purple);
 labelBox(s,'目前仍在进行','正常传播样本库\n更多交互场景\nPlanner接入\n正式攻击实验\n对照与消融实验',{left:675,top:130,width:530,height:430},P.gold);
}

// 15
{
 const s=contentSlide('当前困难',2,'信息流表示本身已经较清晰。更大的开放问题是图如何参与攻击，以及如何验证攻击提升来自图结构。\n来源：docs/论文阅读后关于idea的思考.md。');
 labelBox(s,'信息流分析','图中的关系是否准确\n未观察步骤如何处理\n语义依赖如何验证\n不同轨迹如何统一表示',{left:75,top:135,width:535,height:335},P.purple);
 labelBox(s,'攻击过程','信息流图如何帮助攻击\nPlanner应该关注哪些信息\nPrompt需要怎样组织\nLong-horizon状态如何处理\n攻击提升如何解释',{left:670,top:135,width:535,height:335},P.gold);
 shape(s,'roundRect',{left:210,top:515,width:860,height:64},P.lightPurple,{style:'solid',fill:'#CDBDCF',width:1},12);
 textBox(s,'图到攻击的转换仍需明确',{left:250,top:524,width:780,height:46},{size:25,color:P.deep,bold:true,align:'center'});
}

// 16
{
 const s=contentSlide('论文启发与未来工作',2,'Survey启发只作为可能方向。当前阅读笔记没有提出具体利用机制，因此不在这里扩展攻击规划框架。\n来源：docs/论文阅读后关于idea的思考.md；The Attack and Defense Landscape of Agentic AI: A Comprehensive Survey。');
 labelBox(s,'论文启发','系统整理Agent设计组件\n总结攻击维度和攻击向量\n可能帮助组织攻击Prompt\n可能帮助比较不同攻击方式\n具体方法仍需讨论和实验',{left:70,top:125,width:545,height:400},P.purple);
 labelBox(s,'未来工作','完善正常传播样本\n检查信息流图准确性\n明确信息流图在攻击中的作用\n设计合理的Planner输入\n比较有无信息流图的结果\n分析Long-horizon攻击过程',{left:665,top:125,width:545,height:400},P.gold);
 shape(s,'roundRect',{left:145,top:565,width:990,height:62},P.pale,{style:'solid',fill:P.gold,width:1},12);
 textBox(s,'研究重点逐步转向信息流的攻击利用',{left:190,top:573,width:900,height:46},{size:25,color:P.deep,bold:true,align:'center'});
}

await fs.mkdir(outputDir,{recursive:true});
const stagingDir=path.join(workspaceDir,'.codex-finalizer');
await fs.mkdir(stagingDir,{recursive:true});
const candidatePath=path.join(stagingDir,'candidate-stac-primitive.pptx');
await (await PresentationFile.exportPptx(presentation)).save(candidatePath);
const { finalizePresentation } = await import(pathToFileURL(path.join(SKILL_DIR,'container_tools/artifact_tool_utils.mjs')).href);
const requirements={explicitTotalSlideCount:16,requiredNativeTableOwnerSlides:[],requiredNativeChartOwnerSlides:[]};
const result=await finalizePresentation({
 ...requirements,workspaceDir,candidatePath,finalPath,pythonExecutable:RUNTIME_PYTHON,
 integrityValidatorPath:path.join(SKILL_DIR,'container_tools/inspect_presentation_package_integrity.py'),
 layoutValidatorPath:path.join(SKILL_DIR,'container_tools/inspect_presentation_layout_geometry.py'),
 layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit'],
 fontPolicy:{basis:'design',families:['Noto Sans CJK SC','DejaVu Sans','DejaVu Sans Mono']},
 verifyArtifactToolImport:true,
 receiptPath:path.join(stagingDir,'STAC_Primitive_Research_Update_CUHK.validation.json')
});
console.log(JSON.stringify({finalPath,result},null,2));
