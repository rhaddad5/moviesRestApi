(this.webpackJsonpclient=this.webpackJsonpclient||[]).push([[0],{100:function(e,a,t){},140:function(e,a,t){e.exports=t(302)},145:function(e,a,t){},163:function(e,a,t){},292:function(e,a,t){},293:function(e,a,t){},294:function(e,a,t){},295:function(e,a,t){},298:function(e,a,t){},299:function(e,a,t){},300:function(e,a,t){},301:function(e,a,t){},302:function(e,a,t){"use strict";t.r(a);var n=t(0),r=t.n(n),c=t(24),o=t.n(c),l=(t(145),t(146),t(91),t(9)),i=t(306),s=t(304),m=t(13),u=t.n(m),d=t(6),E=(t(100),t(163),t(309)),v=t(8);function f(e){e.location;var a=Object(n.useState)(""),t=Object(l.a)(a,2),c=t[0],o=t[1],m=Object(n.useState)(""),f=Object(l.a)(m,2),g=f[0],h=f[1],p=Object(n.useState)(!1),b=Object(l.a)(p,2),O=b[0],N=b[1],_=Object(d.f)(),y=Object(v.b)();return r.a.createElement(i.a,null,r.a.createElement(i.a.Group,{controlId:"formBasicEmail"},r.a.createElement(i.a.Label,null,"Email address"),r.a.createElement(i.a.Control,{type:"email",className:"inputLogin",placeholder:"Enter email",onChange:function(e){o(e.target.value)}}),r.a.createElement(i.a.Text,{className:"text-muted"},"We'll never share your email with anyone else.")),r.a.createElement(i.a.Group,{controlId:"formBasicPassword"},r.a.createElement(i.a.Label,null,"Enter Password"),r.a.createElement(i.a.Control,{type:"password",className:"inputLogin",placeholder:"Password",onChange:function(e){h(e.target.value)}})),r.a.createElement(s.a,{variant:"danger",className:"loginSignupBtn",onClick:function(){(function(e,a,t){return u.a.post("http://localhost:8000/users/login",{email:e,password:a}).then((function(e){return sessionStorage.setItem("accessToken",e.data.accessToken),sessionStorage.setItem("imageUrl",e.data.imageUrl),t({type:"LOGGED_IN_USER",payload:{data:e.data.accessToken}}),e})).catch((function(e){return console.log("ERREUR LOGIN POST",e),e}))})(c,g,y).then((function(e){e.response?N(e.response.data):_.push("/")}))}},"Login"),O?r.a.createElement(E.a,{variant:"danger",className:"formAlert"},O):"")}var g=t(139),h=t(85),p=t(86),b=t.n(p),O=t(134),N=t(23),_=function(e,a){var t=N.Util.withSnakeCaseKeys(a);return N.Cloudinary.new().url(e,t)};function y(){return(y=Object(O.a)(b.a.mark((function e(a,t){var n,r;return b.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:n={cloudName:"duoagxeqy",format:"json",type:"list",version:Math.ceil((new Date).getTime()/1e3)},r=_(a.toString(),n),fetch(r).then((function(e){return e.text()})).then((function(e){return e?t(JSON.parse(e).resources.map((function(e){return e.url}))):[]})).catch((function(e){return console.log(e)}));case 3:case"end":return e.stop()}}),e)})))).apply(this,arguments)}function S(){var e=Object(n.useState)(""),a=Object(l.a)(e,2),t=a[0],c=a[1],o=Object(n.useState)(""),m=Object(l.a)(o,2),v=m[0],f=m[1],p=Object(n.useState)(""),b=Object(l.a)(p,2),O=b[0],_=b[1],S=Object(n.useState)(!1),w=Object(l.a)(S,2),I=w[0],j=w[1],k=Object(n.useState)([]),L=Object(l.a)(k,2),R=L[0],T=L[1],D=Object(d.f)(),U=function(){(function(e,a,t,n){return u.a.post("http://localhost:8000/users/signup",{username:e,email:a,password:t,imageUrl:n}).then((function(e){return console.log("REPONSE SIGNUP POST",e),e})).catch((function(e){return console.log("ERREUR SIGNUP POST",e),e}))})(t,v,O).then((function(e){console.log(e.response),e.response?j(e.response.data):D.push("/login")}))},P=function(e){!function(e,a){var t=N.Util.withSnakeCaseKeys(e);window.cloudinary.openUploadWidget(t,a)}({cloudName:"duoagxeqy",tags:[e],uploadPreset:"achmm5wn"},(function(e,a){e?console.log(e):"success"===a.event&&T([].concat(Object(g.a)(R),[a.info.url]))}))};return Object(n.useEffect)((function(){!function(e,a){y.apply(this,arguments)}("image",T)}),[]),r.a.createElement(h.CloudinaryContext,{cloudName:"duoagxeqy"},r.a.createElement(i.a,null,r.a.createElement(i.a.Group,{controlId:"formBasicUsername"},r.a.createElement(i.a.Label,null,"Username"),r.a.createElement(i.a.Control,{type:"username",className:"inputLogin",placeholder:"Enter username",onChange:function(e){e.target.value.length<3?j("Please enter a username"):j(!1),c(e.target.value)}})),r.a.createElement(i.a.Group,{controlId:"formBasicEmail"},r.a.createElement(i.a.Label,null,"Email"),r.a.createElement(i.a.Control,{type:"email",className:"inputLogin",placeholder:"Enter email",onChange:function(e){/^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(e.target.value)?(f(e.target.value),j(!1)):j("Please enter a valid email")}}),r.a.createElement(i.a.Text,{className:"text-muted"},"We'll never share your email with anyone else.")),r.a.createElement(i.a.Group,{controlId:"formBasicPassword"},r.a.createElement(i.a.Label,null,"Enter Password"),r.a.createElement(i.a.Control,{type:"password",className:"inputLogin",placeholder:"Password",onChange:function(e){/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/.test(e.target.value)?(_(e.target.value),j(!1)):j("Your password must contain at least 8 characters with 1 uppercase letter, 1 lowercase letter, 1 number and 1 special character")}})),r.a.createElement(s.a,{onClick:function(){return P()},className:"uploadPhoto"},"\ud83d\udcf7 Upload a photo"),r.a.createElement("br",null),r.a.createElement("section",null,R.map((function(e){return r.a.createElement(h.Image,{key:e,publicId:e,"fetch-format":"auto",quality:"auto"})}))),r.a.createElement("br",null),r.a.createElement(s.a,{variant:"danger",className:"loginSignupBtn",onClick:function(){U()}},"Submit")),I?r.a.createElement(E.a,{variant:"danger",className:"formAlert"},I):"")}t(292);var w=t(305),I=t(132);t(293);function j(){var e=Object(n.useState)(""),a=Object(l.a)(e,2),t=a[0],c=a[1],o=Object(v.b)();return r.a.createElement("div",null,r.a.createElement(w.a,{className:"searchMovies mb-3"},r.a.createElement(I.a,{placeholder:"Look for a movie","aria-label":"Look for a movie","aria-describedby":"basic-addon2",onChange:function(e){c(e.target.value)}}),r.a.createElement(w.a.Append,null,r.a.createElement(s.a,{variant:"outline-secondary",onClick:function(){!function(e,a){u.a.get("https://api.themoviedb.org/3/search/movie?api_key=7ea46f482f53526386b509ee7fe0fe02&query=".concat(e,"&language=en-US")).then((function(e){a({type:"ADD_MOVIES",payload:{data:e.data.results}})})).catch((function(e){return console.log("erreur get movies:",e)}))}(t,o)}},"Search"))))}function k(){return r.a.createElement("div",{className:"banner"},r.a.createElement("div",{className:"container"},r.a.createElement("h1",null,"Your own movie database"),r.a.createElement("p",null,"Find all your favourite movies and save them not to forget them ever again"),r.a.createElement(j,null)))}t(294);var L=t(19);t(79);function R(e){var a=e.movies;return r.a.createElement("div",{className:"container"},r.a.createElement("ul",{className:"cards"},a.map((function(e){var a="https://image.tmdb.org/t/p/w400/".concat(e.poster_path),t="/".concat(e.id);return r.a.createElement(L.b,{to:t,className:"movieLink"},r.a.createElement("li",{className:"cards__item"},r.a.createElement("div",{className:"card"},r.a.createElement("div",{className:"card__image card__image--flowers"},r.a.createElement("img",{src:a,alt:"Movie poster"})),r.a.createElement("div",{className:"card__content"},r.a.createElement("div",{className:"card__title"},e.title),r.a.createElement("h2",{className:"card__text"},e.release_date),r.a.createElement("p",{className:"card__text"},e.overview)))))}))))}function T(e){e.location;var a=Object(v.c)((function(e){return e.moviesListReducer}));return r.a.createElement("div",null,r.a.createElement(k,null),r.a.createElement("div",{className:"container"},r.a.createElement(R,{movies:a})))}t(295);var D=t(30),U=t(21),P=t(87),C=t(88),x=(t(298),function(e){var a=sessionStorage.getItem("accessToken"),t={Authorization:"Bearer ".concat(a)};u.a.get("http://localhost:8000/movies",{headers:t}).then((function(a){e({type:"ADD_FAVOURITE_MOVIES",payload:{data:a.data}}),sessionStorage.setItem("favMovies",JSON.stringify(a.data))})).catch((function(e){return console.log("ERREUR GET FAV",e)}))});function A(e){var a=e.movieTitle,t=e.movieDate,c=e.movieId,o=e.movieOverview,i=e.movieImagePath,s=Object(n.useState)(void 0),m=Object(l.a)(s,2),d=m[0],E=m[1];Object(n.useEffect)((function(){h()}),[]);var f=Object(v.b)(),g=[],h=function(){x(f);var e=JSON.parse(sessionStorage.getItem("favMovies"));e&&(e.forEach((function(e){e.tmdbId===parseInt(c,10)&&g.push(!0)})),g[0]?E(!0):E(!1))},p=function(){var e;E(!d),d?(e=c,u.a.delete("http://localhost:8000/movies/".concat(e)).then((function(e){return console.log("REPONSE DELETE",e)})).catch((function(e){return console.log("ERREUR DELETE",e)}))):function(e,a,t,n,r){var c=sessionStorage.getItem("accessToken"),o={Authorization:"Bearer ".concat(c)};u.a.post("http://localhost:8000/movies",{title:e,releaseDate:a,tmdbId:t,overview:n,imagePath:r},{headers:o}).then((function(e){return console.log("REPONSE POST",e)})).catch((function(e){return console.log("ERREUR POST",e)}))}(a,t,c,o,i)};return r.a.createElement("div",{className:"icon"},d?r.a.createElement(U.a,{icon:P.a,onClick:p}):r.a.createElement(U.a,{icon:C.a,onClick:p}))}function M(){var e=Object(v.b)(),a=Object(d.g)().id;Object(n.useEffect)((function(){!function(e,a){u.a.get("https://api.themoviedb.org/3/movie/".concat(e,"?api_key=7ea46f482f53526386b509ee7fe0fe02&language=en-US")).then((function(e){a({type:"ADD_MOVIE_DETAILS",payload:{data:e.data}})})).catch((function(e){return console.log("erreur get movie:",e)}))}(a,e)}),[]);var t=Object(v.c)((function(e){return e.movieDetailsReducer})),c="https://image.tmdb.org/t/p/w400/".concat(t.poster_path);return r.a.createElement("div",{className:"movieDetails container"},r.a.createElement("li",{className:"cards__item"},r.a.createElement("div",{className:"card"},r.a.createElement("div",{className:"card__image card__image--flowers"},r.a.createElement("img",{src:c,alt:"Movie poster"})),r.a.createElement("div",{className:"card__content"},r.a.createElement("div",{className:"card__title"},t.title),r.a.createElement("h2",{className:"card__text"},t.release_date),r.a.createElement("p",{className:"card__text"},t.overview),sessionStorage.getItem("accessToken")?r.a.createElement(A,{className:"star",movieTitle:t.title,movieDate:t.release_date,movieId:a,movieOverview:t.overview,movieImagePath:c}):""))))}D.b.add(P.a,C.a);t(299);function G(){var e=Object(v.b)();Object(n.useEffect)((function(){x(e)}),[]);var a=Object(v.c)((function(e){return e.favMoviesReducer})),t=[];return a.map((function(e){return t.push(e.user)})),r.a.createElement("div",null,a[0]?r.a.createElement("h1",{className:"favTitle"},"Hi ",t[0],"! Here is your movie list"):r.a.createElement("h1",{className:"favTitle noFavTitle"},"Hi! You do not have any movie in your list yet, click here to add some!"),r.a.createElement("ul",{className:"cards"},a.map((function(e){var a="/".concat(e.tmdbId);return r.a.createElement(L.b,{to:a,className:"movieLink"},r.a.createElement("li",{className:"cards__item"},r.a.createElement("div",{className:"card"},r.a.createElement("div",{className:"card__image card__image--flowers"},r.a.createElement("img",{src:e.imagePath,alt:"Movie poster"})),r.a.createElement("div",{className:"card__content"},r.a.createElement("div",{className:"card__title"},e.title),r.a.createElement("h2",{className:"card__text"},e.releaseDate),r.a.createElement("p",{className:"card__text"},e.overview)))))}))))}t(300);var B=t(308),V=t(307);function q(){var e=Object(v.b)(),a=Object(v.c)((function(e){return e.loggedInReducer})),t=sessionStorage.getItem("imageUrl");return r.a.createElement(B.a,{bg:"light"},a[0]?r.a.createElement(V.a,{className:"ml-auto"},r.a.createElement(V.a.Link,{href:"/"},"Home"),r.a.createElement(V.a.Link,{href:"/mymovies"},"My movies"),r.a.createElement(V.a.Link,{href:"#",onClick:function(){var a;sessionStorage.removeItem("accessToken"),sessionStorage.removeItem("imageUrl"),sessionStorage.removeItem("movies"),sessionStorage.removeItem("favMovies"),e({type:"LOGGED_OUT_USER",payload:{data:a}}),document.location.reload(!0)}},"Logout"),r.a.createElement(V.a.Link,{href:"#pricing"},r.a.createElement("img",{className:"avatar dropdown-toggle",src:t,alt:"User avatar"}))):r.a.createElement(V.a,{className:"ml-auto"},r.a.createElement(V.a.Link,{href:"/"},"Home"),r.a.createElement(V.a.Link,{href:"/login"},"Login"),r.a.createElement(V.a.Link,{href:"/signup"},"Signup")))}t(301);var z=t(138);function F(){return r.a.createElement("div",{className:"footer"},r.a.createElement("div",{className:"footer-links"},r.a.createElement("a",{href:"/"},r.a.createElement(U.a,{icon:["fab","github"]})),r.a.createElement("a",{href:"/"},r.a.createElement(U.a,{icon:["fab","instagram"]})),r.a.createElement("a",{href:"/"},r.a.createElement(U.a,{icon:["fab","facebook"]})),r.a.createElement("a",{href:"/"},r.a.createElement(U.a,{icon:["fab","twitter"]})),r.a.createElement("a",{href:"/"},r.a.createElement(U.a,{icon:["fab","linkedin"]}))),r.a.createElement("div",{className:"footer-copyright"},"This website functions thanks to the ",r.a.createElement("a",{href:"https://www.themoviedb.org/",target:"_blank",rel:"noopener noreferrer"},"The Movie Database API")))}function H(){return r.a.createElement(L.a,null,r.a.createElement("div",{className:"App"},r.a.createElement(q,null),r.a.createElement(d.c,null,r.a.createElement(d.a,{exact:!0,path:"/",component:T}),r.a.createElement(d.a,{exact:!0,path:"/signup",component:S}),r.a.createElement(d.a,{exact:!0,path:"/login",component:f}),r.a.createElement(d.a,{exact:!0,path:"/mymovies",component:G}),r.a.createElement(d.a,{exact:!0,path:"/:id",component:M})),r.a.createElement(F,null)))}D.b.add(z.a);var J=function(){return r.a.createElement(H,null)};Boolean("localhost"===window.location.hostname||"[::1]"===window.location.hostname||window.location.hostname.match(/^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/));var W=t(34),$=[],Y=[],Z=[],K=[],Q=Object(W.b)({moviesListReducer:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:$,a=arguments.length>1?arguments[1]:void 0;switch(a.type){case"ADD_MOVIES":return a.payload.data;default:return e}},favMoviesReducer:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:Y,a=arguments.length>1?arguments[1]:void 0;switch(a.type){case"ADD_FAVOURITE_MOVIES":return a.payload.data;default:return e}},movieDetailsReducer:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:Z,a=arguments.length>1?arguments[1]:void 0;switch(a.type){case"ADD_MOVIE_DETAILS":return a.payload.data;default:return e}},loggedInReducer:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:K,a=arguments.length>1?arguments[1]:void 0;switch(a.type){case"LOGGED_IN_USER":case"LOGGED_OUT_USER":return a.payload.data;default:return e}}}),X=Object(W.c)(Q);o.a.render(r.a.createElement(r.a.StrictMode,null,r.a.createElement(v.a,{store:X},r.a.createElement(J,null))),document.getElementById("root")),"serviceWorker"in navigator&&navigator.serviceWorker.ready.then((function(e){e.unregister()})).catch((function(e){console.error(e.message)}))},79:function(e,a,t){},91:function(e,a,t){}},[[140,1,2]]]);
//# sourceMappingURL=main.86dad633.chunk.js.map