(function(a){var c={},e=function(i){var j=[],k=!1,l=i.dir&&'left'===i.dir?'scrollLeft':'scrollTop';return this.each(function(){var m=a(this);return this===document||this===window?void 0:document.scrollingElement&&(this===document.documentElement||this===document.body)?(j.push(document.scrollingElement),!1):void(0<m[l]()?j.push(this):(m[l](1),k=0<m[l](),k&&j.push(this),m[l](0)))}),j.length||this.each(function(){this===document.documentElement&&'smooth'===a(this).css('scrollBehavior')&&(j=[this]),j.length||'BODY'!==this.nodeName||(j=[this])}),'first'===i.el&&1<j.length&&(j=[j[0]]),j},f=/^([\-\+]=)(\d+)/;a.fn.extend({scrollable:function(i){var j=e.call(this,{dir:i});return this.pushStack(j)},firstScrollable:function(i){var j=e.call(this,{el:'first',dir:i});return this.pushStack(j)},smoothScroll:function(i,j){if(i=i||{},'options'===i)return j?this.each(function(){var m=a(this),n=a.extend(m.data('ssOpts')||{},j);a(this).data('ssOpts',n)}):this.first().data('ssOpts');var k=a.extend({},a.fn.smoothScroll.defaults,i),l=function(m){var n=function(C){return C.replace(/(:|\.|\/)/g,'\\$1')},o=this,p=a(this),q=a.extend({},k,p.data('ssOpts')||{}),r=k.exclude,s=q.excludeWithin,t=0,u=0,v=!0,w={},x=a.smoothScroll.filterPath(location.pathname),y=a.smoothScroll.filterPath(o.pathname),z=location.hostname===o.hostname||!o.hostname,A=q.scrollTarget||y===x,B=n(o.hash);if(B&&!a(B).length&&(v=!1),!q.scrollTarget&&(!z||!A||!B))v=!1;else{for(;v&&t<r.length;)p.is(n(r[t++]))&&(v=!1);for(;v&&u<s.length;)p.closest(s[u++]).length&&(v=!1)}v&&(q.preventDefault&&m.preventDefault(),a.extend(w,q,{scrollTarget:q.scrollTarget||B,link:o}),a.smoothScroll(w))};return null===i.delegateSelector?this.off('click.smoothscroll').on('click.smoothscroll',l):this.off('click.smoothscroll',i.delegateSelector).on('click.smoothscroll',i.delegateSelector,l),this}});var g=function(i){var j={relative:''},k='string'==typeof i&&f.exec(i);return'number'==typeof i?j.px=i:k&&(j.relative=k[1],j.px=parseFloat(k[2])||0),j},h=function(i){var j=a(i.scrollTarget);i.autoFocus&&j.length&&(j[0].focus(),!j.is(document.activeElement)&&(j.prop({tabIndex:-1}),j[0].focus())),i.afterScroll.call(i.link,i)};a.smoothScroll=function(i,j){if('options'===i&&'object'==typeof j)return a.extend(c,j);var k,l,m,n,o=g(i),p={},q=0,r='offset',s='scrollTop',t={},u={};o.px?k=a.extend({link:null},a.fn.smoothScroll.defaults,c):(k=a.extend({link:null},a.fn.smoothScroll.defaults,i||{},c),k.scrollElement&&(r='position','static'===k.scrollElement.css('position')&&k.scrollElement.css('position','relative')),j&&(o=g(j))),s='left'===k.direction?'scrollLeft':s,k.scrollElement?(l=k.scrollElement,!o.px&&!/^(?:HTML|BODY)$/.test(l[0].nodeName)&&(q=l[s]())):l=a('html, body').firstScrollable(k.direction),k.beforeScroll.call(l,k),p=o.px?o:{relative:'',px:a(k.scrollTarget)[r]()&&a(k.scrollTarget)[r]()[k.direction]||0},t[s]=p.relative+(p.px+q+k.offset),m=k.speed,'auto'===m&&(n=Math.abs(t[s]-l[s]()),m=n/k.autoCoefficient),u={duration:m,easing:k.easing,complete:function(){h(k)}},k.step&&(u.step=k.step),l.length?l.stop().animate(t,u):h(k)},a.smoothScroll.version='2.2.0',a.smoothScroll.filterPath=function(i){return i=i||'',i.replace(/^\//,'').replace(/(?:index|default).[a-zA-Z]{3,4}$/,'').replace(/\/$/,'')},a.fn.smoothScroll.defaults={exclude:[],excludeWithin:[],offset:0,direction:'top',delegateSelector:null,scrollElement:null,scrollTarget:null,autoFocus:!1,beforeScroll:function(){},afterScroll:function(){},easing:'swing',speed:400,autoCoefficient:2,preventDefault:!0}})(jQuery);