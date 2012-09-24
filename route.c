/*
    route.c -- Route Management

    This module implements the loading of a route configuration file
    and the routing of requests.

    The route configuration is loaded form a text file that uses the schema (see route.txt)
        uri: type: uri: method: ability [ability...]: redirect
        user: name: password: role [role...]
        role: name: ability [ability...]

    Copyright (c) All Rights Reserved. See details at the end of the file.
*/

/********************************* Includes ***********************************/

#include    "goahead.h"

/*********************************** Locals ***********************************/

static WebsRoute **routes = 0;
static WebsHash handlers = -1;
static int routeCount = 0;
static int routeMax = 0;

#define WEBS_MAX_ROUTE 16               /* Maximum passes over route set */

/********************************** Forwards **********************************/

static bool continueHandler(Webs *wp);
static void freeRoute(WebsRoute *route);
static void growRoutes();
static int lookupRoute(char *uri);
static bool redirectHandler(Webs *wp);

/************************************ Code ************************************/

void websRouteRequest(Webs *wp)
{
    WebsRoute   *route;
    ssize       plen, len;
    bool        safeMethod;
    int         i, count;

    safeMethod = smatch(wp->method, "POST") || smatch(wp->method, "GET") || smatch(wp->method, "HEAD");

    plen = slen(wp->path);
    for (count = 0, i = 0; i < routeCount; i++) {
        route = routes[i];
        if (plen < route->prefixLen) continue;
        len = min(route->prefixLen, plen);
        trace(5, "Examine route %s\n", route->prefix);
        /*
            Match route
         */
        if (route->protocol && !smatch(route->protocol, wp->protocol)) {
            trace(5, "Route %s doesnt match protocol %s\n", route->prefix, wp->protocol);
            continue;
        }
        if (route->methods >= 0) {
            if (!symLookup(route->methods, wp->method)) {
                trace(5, "Route %s doesnt match method %s\n", route->prefix, wp->method);
                continue;
            }
        } else if (!safeMethod) {
            continue;
        }
        if (route->extensions >= 0 && (wp->ext == 0 || !symLookup(route->extensions, &wp->ext[1]))) {
            trace(5, "Route %s doesn match extension %s\n", route->prefix, wp->ext ? wp->ext : "");
            continue;
        }
        if (strncmp(wp->path, route->prefix, len) == 0) {
            wp->route = route;
            if (route->authType && !websAuthenticate(wp)) {
                return;
            }
            if (route->abilities >= 0 && !websCan(wp, route->abilities)) {
                return;
            }
            websSetEnv(wp);
#if BIT_LEGACY
            if (route->handler->flags & WEBS_LEGACY_HANDLER) {
                if ((*(WebsLegacyHandlerProc) route->handler->service)(wp, route->prefix, route->dir, route->flags)) {
                    return;
                }
            } else
#endif
            trace(5, "Route %s calls handler %s\n", route->prefix, route->handler->name);
            if ((*route->handler->service)(wp)) {                                        
                return;
            }
            if (wp->flags & WEBS_REROUTE) {
                wp->flags &= ~WEBS_REROUTE;
                if (++count >= WEBS_MAX_ROUTE) {
                    break;
                }
                i = 0;
            }
            if (!websValid(wp)) {
                trace(5, "handler %s called websDone, but didn't return 1\n", route->handler->name);
                return;
            }
        }
    }
    if (count >= WEBS_MAX_ROUTE) {
        error("Route loop for %s", wp->url);
    }
    websError(wp, HTTP_CODE_NOT_ACCEPTABLE, "Can't find suitable route for request.");
}


static bool can(Webs *wp, char *ability)
{
    if (wp->user && symLookup(wp->user->abilities, ability)) {
        return 1;
    }
    return 0;
}


bool websCan(Webs *wp, WebsHash abilities) 
{
    WebsKey     *key;
    char        *ability, *cp, *start, abuf[BIT_LIMIT_STRING];

    if (!wp->user) {
        if (wp->authType) {
            if (!wp->username) {
                websError(wp, 401, "Access Denied. User not logged in.");
                return 0;
            }
            if ((wp->user = websLookupUser(wp->username)) == 0) {
                websError(wp, 401, "Access Denied. Unknown user.");
                return 0;
            }
        }
    }
    if (abilities >= 0) {
        if (!wp->user && wp->username) {
            wp->user = websLookupUser(wp->username);
        }
        gassert(abilities);
        for (key = symFirst(abilities); key; key = symNext(abilities, key)) {
            ability = key->name.value.string;
            if ((cp = strchr(ability, '|')) != 0) {
                /*
                    Examine a set of alternative abilities. Need only one to match
                 */ 
                start = ability;
                do {
                    sncopy(abuf, sizeof(abuf), start, cp - start);
                    if (can(wp, abuf)) {
                        break;
                    }
                    if (websComplete(wp)) {
                        return 0;
                    }
                    start = &cp[1];
                } while ((cp = strchr(start, '|')) != 0);
                if (!cp) {
                    websError(wp, 401, "Access Denied. Insufficient capabilities.");
                    return 0;
                }
            } else if (!can(wp, ability)) {
                websError(wp, 401, "Access Denied. Insufficient capabilities.");
                return 0;
            }
        }
    }
    return 1;
}


//  MOB fix
bool websCanString(Webs *wp, char *abilities) 
{
    WebsUser    *user;
    char        *ability, *tok;

    if (!wp->user) {
        if (!wp->username) {
            return 0;
        }
        if ((user = websLookupUser(wp->username)) == 0) {
            trace(2, "Can't find user %s\n", wp->username);
            return 0;
        }
    }
    abilities = strdup(abilities);
    for (ability = stok(abilities, " \t,", &tok); ability; ability = stok(NULL, " \t,", &tok)) {
        if (symLookup(wp->user->abilities, ability) == 0) {
            gfree(abilities);
            return 0;
        }
    }
    gfree(abilities);
    return 1;
}


/*
    If pos is < 0, then add to the end. Otherwise insert at specified position
 */
WebsRoute *websAddRoute(char *uri, char *handler, int pos)
{
    WebsRoute   *route;
    WebsKey     *key;

    if (uri == 0 || *uri == '\0') {
        error("Bad URI");
        return 0;
    }
    if ((route = galloc(sizeof(WebsRoute))) == 0) {
        return 0;
    }
    memset(route, 0, sizeof(WebsRoute));
    route->prefix = sclone(uri);
    route->prefixLen = slen(uri);
    route->abilities = route->extensions = route->methods = route->redirects = -1;
    if (!handler) {
        handler = "file";
    }
    if ((key = symLookup(handlers, handler)) == 0) {
        error("Can't find handler %s", handler);
        return 0;
    }
    route->handler = key->content.value.symbol;
#if BIT_PAM
    route->verify = websVerifyPamUser;
#else
    route->verify = websVerifyUser;
#endif
    growRoutes();
    if (pos < 0) {
        pos = routeCount;
    } 
    if (pos < routeCount) {
        memmove(&routes[pos + 1], &routes[pos], sizeof(WebsRoute*) * routeCount - pos);
    }
    routes[pos] = route;
    routeCount++;
    return route;
}


int websSetRouteMatch(WebsRoute *route, char *dir, char *protocol, WebsHash methods, WebsHash extensions, 
        WebsHash abilities, WebsHash redirects)
{
    route->dir = dir ? dir : websGetDocuments();
    route->protocol = protocol ? sclone(protocol) : 0;
    route->abilities = abilities;
    route->extensions = extensions;
    route->methods = methods;
    route->redirects = redirects;
    return 0;
}


int websSetRouteAuth(WebsRoute *route, char *auth)
{
    WebsParseAuth parseAuth;
    WebsAskLogin  askLogin;

    askLogin = 0;
    parseAuth = 0;
    if (smatch(auth, "basic")) {
        askLogin = websBasicLogin;
        parseAuth = websParseBasicDetails;
#if BIT_DIGEST
    } else if (smatch(auth, "digest")) {
        askLogin = websDigestLogin;
        parseAuth = websParseDigestDetails;
#endif
    } else if (smatch(auth, "form")) {
        askLogin = websFormLogin;
    } else {
        auth = 0;
    }
    route->authType = sclone(auth);
    route->askLogin = askLogin;
    route->parseAuth = parseAuth;
    return 0;
}


static void growRoutes()
{
    if (routeCount >= routeMax) {
        routeMax += 16;
        //  RC
        routes = grealloc(routes, sizeof(WebsRoute*) * routeMax);
    }
}


static int lookupRoute(char *uri) 
{
    WebsRoute   *route;
    int         i;

    for (i = 0; i < routeCount; i++) {
        route = routes[i];
        if (smatch(route->prefix, uri)) {
            return i;
        }
    }
    return -1;
}


static void freeRoute(WebsRoute *route)
{
    if (route->abilities >= 0) {
        symClose(route->abilities);
    }
    if (route->extensions >= 0) {
        symClose(route->extensions);
    }
    if (route->methods >= 0) {
        symClose(route->methods);
    }
    if (route->redirects >= 0) {
        symClose(route->redirects);
    }
    gfree(route->prefix);
    gfree(route->dir);
    gfree(route->protocol);
    gfree(route->authType);
    gfree(route->handler);
    gfree(route);
}


int websRemoveRoute(char *uri) 
{
    int         i;

    if ((i = lookupRoute(uri)) < 0) {
        return -1;
    }
    freeRoute(routes[i]);
    for (; i < routeCount; i++) {
        routes[i] = routes[i+1];
    }
    routeCount--;
    return 0;
}


int websOpenRoute(char *path) 
{
    if ((handlers = symOpen(-1)) < 0) {
        return -1;
    }
    websDefineHandler("continue", continueHandler, 0, 0);
    websDefineHandler("redirect", redirectHandler, 0, 0);
    return 0;
}


void websCloseRoute() 
{
    WebsKey     *key;
    WebsHandler *handler;

    if (handlers >= 0) {
        for (key = symFirst(handlers); key; key = symNext(handlers, key)) {
            handler = key->content.value.symbol;
            if (handler->close) {
                (*handler->close)();
            }
            gfree(handler->name);
        }
        symClose(handlers);
        handlers = -1;
    }
    if (routes) {
        gfree(routes);
        routes = 0;
    }
    routeCount = routeMax = 0;
}


int websDefineHandler(char *name, WebsHandlerProc service, WebsHandlerClose close, int flags)
{
    WebsHandler     *handler;

    if ((handler = galloc(sizeof(WebsHandler))) == 0) {
        return -1;
    }
    memset(handler, 0, sizeof(WebsHandler));
    handler->name = sclone(name);
    handler->service = service;
    handler->close = close;
    handler->flags = flags;

    symEnter(handlers, name, valueSymbol(handler), 0);
    return 0;
}


#if !BIT_ROM
static void addOption(WebsHash *hash, char *keys, char *value)
{
    char    *sep, *key, *tok;

    if (*hash < 0) {
        *hash = symOpen(-1);
    }
    sep = " \t,|";
    for (key = stok(keys, sep, &tok); key; key = stok(0, sep, &tok)) {
        if (strcmp(key, "none") == 0) {
            continue;
        }
        if (value == 0) {
            symEnter(*hash, key, valueInteger(0), 0);
        } else {
            symEnter(*hash, key, valueString(value, VALUE_ALLOCATE), 0);
        }
    }
}


int websLoadRoutes(char *path)
{
    WebsRoute     *route;
    FILE          *fp;
    char          buf[512], *line, *kind, *next, *auth, *dir, *handler, *protocol, *uri, *option, *key, *value, *status;
    char          *name, *redirectUri, *password, *roles;
    WebsHash      abilities, extensions, methods, redirects;
    int           i;
    
    if ((fp = fopen(path, "rt")) == 0) {
        error("Can't open route config file %s", path);
        return -1;
    }
    buf[sizeof(buf) - 1] = '\0';
    while ((line = fgets(buf, sizeof(buf) -1, fp)) != 0) {
        kind = stok(buf, " \t\r\n", &next);
        // for (cp = kind; cp && isspace((uchar) *cp); cp++) { }
        if (kind == 0 || *kind == '\0' || *kind == '#') {
            continue;
        }
        if (smatch(kind, "route")) {
            auth = dir = handler = protocol = uri = 0;
            abilities = extensions = methods = redirects = -1;
            while ((option = stok(NULL, " \t\r\n", &next)) != 0) {
                key = stok(option, "=", &value);
                if (smatch(key, "abilities")) {
                    addOption(&abilities, value, 0);
                } else if (smatch(key, "auth")) {
                    auth = value;
                } else if (smatch(key, "dir")) {
                    dir = value;
                } else if (smatch(key, "extensions")) {
                    addOption(&extensions, value, 0);
                } else if (smatch(key, "handler")) {
                    handler = value;
                } else if (smatch(key, "methods")) {
                    addOption(&methods, value, 0);
                } else if (smatch(key, "redirect")) {
                    if (strchr(value, '@')) {
                        status = stok(value, "@", &redirectUri);
                        if (smatch(status, "*")) status = "0";
                    } else {
                        status = "0";
                        redirectUri = value;
                    }
                    if (smatch(redirectUri, "https")) redirectUri = "https://";
                    if (smatch(redirectUri, "http")) redirectUri = "http://";
                    addOption(&redirects, status, redirectUri);
                } else if (smatch(key, "protocol")) {
                    protocol = value;
                } else if (smatch(key, "uri")) {
                    uri = value;
                } else {
                    error("Bad route keyword %s", key);
                    continue;
                }
            }
            if ((route = websAddRoute(uri, handler, -1)) == 0) {
                return -1;
            }
            websSetRouteMatch(route, dir, protocol, methods, extensions, abilities, redirects);
            if (auth && websSetRouteAuth(route, auth) < 0) {
                return -1;
            }
        } else if (smatch(kind, "user")) {
            name = password = roles = 0;
            while ((option = stok(NULL, " \t\r\n", &next)) != 0) {
                key = stok(option, "=", &value);
                if (smatch(key, "name")) {
                    name = value;
                } else if (smatch(key, "password")) {
                    password = value;
                } else if (smatch(key, "roles")) {
                    roles = value;
                } else {
                    error("Bad user keyword %s", key);
                    continue;
                }
            }
            if (websAddUser(name, password, roles) == 0) {
                return -1;
            }
        } else if (smatch(kind, "role")) {
            name = 0;
            abilities = -1;
            while ((option = stok(NULL, " \t\r\n", &next)) != 0) {
                key = stok(option, "=", &value);
                if (smatch(key, "name")) {
                    name = value;
                } else if (smatch(key, "abilities")) {
                    addOption(&abilities, value, 0);
                }
            }
            if (websAddRole(name, abilities) < 0) {
                return -1;
            }
        } else {
            error("Unknown route keyword %s", kind); 
            return -1;
        }
    }
    fclose(fp);
    /*
        Ensure there is a route for "/", if not, create it.
     */
    for (i = 0, route = 0; i < routeCount; i++) {
        route = routes[i];
        if (strcmp(route->prefix, "/") == 0) {
            break;
        }
    }
    if (i >= routeCount) {
        websAddRoute("/", 0, -1);
    }
    websComputeAllUserAbilities();
    return 0;
}
#endif


int websSaveRoute(char *path)
{
    //  MOB TODO
    return 0;
}


static bool continueHandler(Webs *wp)
{
    return 0;
}


static bool redirectHandler(Webs *wp)
{
    WebsRoute   *route;

    route = wp->route;
    return websRedirectByStatus(wp, 0) == 0;
}



#if BIT_LEGACY
int websUrlHandlerDefine(char *prefix, char *dir, int arg, WebsLegacyHandlerProc handler, int flags)
{
    WebsRoute   *route;
    static int  legacyCount = 0;
    char        name[BIT_LIMIT_STRING];

    fmt(name, sizeof(name), "%s-%d", prefix, legacyCount);
    if (websDefineHandler(name, (WebsHandlerProc) handler, 0, WEBS_LEGACY_HANDLER) < 0) {
        return -1;
    }
    if ((route = websAddRoute(prefix, name, 0)) == 0) {
        return -1;
    }
    if (dir) {
        route->dir = sclone(dir);
    }
    return 0;
}


int websPublish(char *prefix, char *dir)
{
    WebsRoute   *route;

    if ((route = websAddRoute(prefix, 0, 0)) == 0) {
        return -1;
    }
    route->dir = sclone(dir);
    return 0;
}
#endif


/*
    @copy   default

    Copyright (c) Embedthis Software LLC, 2003-2012. All Rights Reserved.

    This software is distributed under commercial and open source licenses.
    You may use the Embedthis GoAhead open source license or you may acquire 
    a commercial license from Embedthis Software. You agree to be fully bound
    by the terms of either license. Consult the LICENSE.md distributed with
    this software for full details and other copyrights.

    Local variables:
    tab-width: 4
    c-basic-offset: 4
    End:
    vim: sw=4 ts=4 expandtab

    @end
 */
