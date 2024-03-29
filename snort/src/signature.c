/*
** Copyright (C) 2002 Sourcefire, Inc.
** Author(s):   Andrew R. Baker <andrewb@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <string.h>
#include <ctype.h>
#include "signature.h"
#include "util.h"
#include "rules.h"
#include "mstring.h"
#include "sfutil/sfghash.h"

#ifdef TARGET_BASED
#include "target-based/sftarget_protocol_reference.h"
#endif

extern char *file_name;
extern int file_line;

static OptTreeNode *soidOTN;

SFGHASH * soid_sg_otn_map = NULL;
SFGHASH * sg_rule_otn_map = NULL;

/********************* Reference Implementation *******************************/

ReferenceNode *AddReference(ReferenceNode *rn, char *system, char *id)
{
    ReferenceNode *newNode;

    if(system == NULL || id == NULL)
    {
        ErrorMessage("NULL reference argument\n");
        return rn;
    }
    
    /* create the new node */
    newNode = (ReferenceNode *)SnortAlloc(sizeof(ReferenceNode));
    
    /* lookup the reference system */
    newNode->system = ReferenceSystemLookup(system);
    if (!newNode->system)
    {
        newNode->system = ReferenceSystemAdd(system, NULL);
    }
    newNode->id = SnortStrdup(id);
    
    /* add the node to the list */
    newNode->next = rn;
    
    return newNode;
}

/* print a reference node */
void FPrintReference(FILE *fp, ReferenceNode *refNode)
{
    if(refNode)
    {
        if(refNode->system)
        {
            if(refNode->system->url)
                fprintf(fp, "[Xref => %s%s]", refNode->system->url, 
                        refNode->id);
            else
                fprintf(fp, "[Xref => %s %s]", refNode->system->name,
                        refNode->id);
        }
        else
        {
            fprintf(fp, "[Xref => %s]", refNode->id);
        }
    }
    return;   
}

void ParseReference(char *args, OptTreeNode *otn)
{
    char **toks, *system, *id;
    int num_toks;

    /* 2 tokens: system, id */
    toks = mSplit(args, ",", 2, &num_toks, 0);
    if(num_toks != 2)
    {
        LogMessage("WARNING %s(%d): invalid Reference spec '%s'.  Ignored\n",
                file_name, file_line, args);
    }
    else
    {
        system = toks[0];
        while ( isspace((int) *system) )
            system++;

        id = toks[1];
        while ( isspace((int) *id) )
            id++;
            
        otn->sigInfo.refs = AddReference(otn->sigInfo.refs, system, id);
    }

    mSplitFree(&toks, num_toks);

    return;
}


/********************* End of Reference Implementation ************************/

/********************** Reference System Implementation ***********************/

ReferenceSystemNode *referenceSystems = NULL;

ReferenceSystemNode *ReferenceSystemAdd(char *name, char *url)
{   
    ReferenceSystemNode *newNode;
    if(name == NULL)
    {
        ErrorMessage("NULL reference system name\n");
        return NULL;
    }

    /* create the new node */
    newNode = (ReferenceSystemNode *)SnortAlloc(sizeof(ReferenceSystemNode));

    newNode->name = SnortStrdup(name);
    if(url)
        newNode->url = SnortStrdup(url);
    else
        newNode->url = NULL;

    /* add to the list */
    newNode->next = referenceSystems;
    referenceSystems = newNode;
    return newNode;
}

ReferenceSystemNode *ReferenceSystemLookup(char *name)
{   
    ReferenceSystemNode *refSysNode = referenceSystems;
    while(refSysNode)
    {
        if(strcasecmp(name, refSysNode->name) == 0)
            return refSysNode;
        refSysNode = refSysNode->next;
    }
    return NULL;
}

void ParseReferenceSystemConfig(char *args)
{
    char **toks;
    char *name = NULL;
    char *url = NULL;
    int num_toks;

    /* 2 tokens: name <url> */
    toks = mSplit(args, " ", 2, &num_toks, 0);
    name = toks[0];
    if(num_toks == 2)
    {
        url = toks[1];
        while(isspace((int)*url))
            url++;
        if(url[0] == '\0')
            url = NULL;
    }
    ReferenceSystemAdd(name, url);

    mSplitFree(&toks, num_toks);
    return;
}

/****************** End of Reference System Implementation ********************/

/********************* Miscellaneous Parsing Functions ************************/

void ParseSID(char *sid, OptTreeNode *otn)
{
    if(sid != NULL)
    {
        while(isspace((int)*sid)) { sid++; }

        if(isdigit((int)sid[0]))
        {
            otn->sigInfo.id = atoi(sid);
            /* deprecated */
            otn->event_data.sig_id = atoi(sid);
            return;
        }

        LogMessage("WARNING %s(%d) => Bad SID found: %s\n", file_name, 
                file_line, sid);
        return;
    }

    LogMessage("WARNING %s(%d) => SID found without ID number\n", file_name, 
               file_line);

    return;
}

void ParseGID(char *gid, OptTreeNode *otn)
{
    if(gid != NULL)
    {
        while(isspace((int)*gid)) { gid++; }

        if(isdigit((int)gid[0]))
        {
            otn->sigInfo.generator = atoi(gid);
            otn->event_data.sig_generator = atoi(gid);
            return;
        }

        LogMessage("WARNING %s(%d) => Bad GID found: %s\n", file_name, 
                file_line, gid);
        return;
    }

    LogMessage("WARNING %s(%d) => GID found without ID number\n", file_name, 
               file_line);

    return;
}
void ParseRev(char *rev, OptTreeNode *otn)
{
    if(rev != NULL)
    {
        while(isspace((int)*rev)) { rev++; }

        if(isdigit((int)rev[0]))
        {
            otn->sigInfo.rev = atoi(rev);
            /* deprecated */
            otn->event_data.sig_rev = atoi(rev);
            return;
        }

        LogMessage("WARNING %s(%d) => Bad Rev found: %s\n", file_name, 
            file_line, rev);
                
        return;
    }

    LogMessage("WARNING %s(%d) => Rev found without number!\n", file_name, 
            file_line);

    return;
}
/****************** End of Miscellaneous Parsing Functions ********************/

/************************ Class/Priority Implementation ***********************/

ClassType *classTypes = NULL;

int AddClassificationConfig(ClassType *newNode);

void ParsePriority(char *priority, OptTreeNode *otn)
{
    if(priority != NULL)
    {
        while(isspace((int)*priority))
            priority++;

        if(isdigit((int)priority[0]))
        {
            otn->sigInfo.priority = atoi(priority);
            /* deprecated */
            otn->event_data.priority = atoi(priority);
            return;
        }

        LogMessage("WARNING %s(%d) => Bad Priority: %s\n", file_name, 
                file_line, priority);

        return;
    }

    LogMessage("WARNING %s(%d) => Priority without an argument!\n", file_name, 
            file_line);

    return;
}
/*
 * metadata may be key/value pairs or just keys
 * 
 * metadata: key [=] value, key [=] value, key [=] value, key, key, ... ;
 *
 * This option may be used one or more times, with one or more key/value pairs.
 *
 * updated 8/28/06 - man 
 *
 * keys:
 * 
 * engine
 * rule-flushing
 * rule-type
 * soid
 * service 
 * os
 */
void ParseMetadata(char * metadata, OptTreeNode *otn)
{
    char * key;
    char * value;
    char **toks;
    int    num_toks;
    char **key_toks;
    int    num_keys;
    char  *endPtr;
    int    i;

    if( !metadata )
    {
        LogMessage("WARNING %s(%d) => Metadata without an argument!\n", 
            file_name,file_line);
        return;
    }
    
    while(isspace((int)*metadata)) 
        metadata++;
    
    if( !strlen(metadata) ) return;
  
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "metadata: %s\n",metadata););
    
    key_toks = mSplit(metadata, ",", 100, &num_keys, 0);
   
    for(i=0;i<num_keys;i++)
    {

        /* keys are requied .. */
        key   = strtok(key_toks[i]," =");
        if( !key  )
        {
            mSplitFree(&key_toks, num_keys);
            return;
        }

        /* values are optional - depends on key */
        value = strtok(0," ");
    
        DEBUG_WRAP(
            DebugMessage(DEBUG_CONFIGRULES, "metadata: key=%s",key);
            if(value)
                DebugMessage(DEBUG_CONFIGRULES, " value=%s",value);
            DebugMessage(DEBUG_CONFIGRULES, "\n");
        );
       
        /* 
         * process key/valuies 
         */
        if( strcmp(key,"engine")==0 )
        {
            if( !value )
                FatalError("metadata key '%s' requires a value\n",key);
            
            if( strcmp(value,"shared")==0 )
            {
                otn->sigInfo.shared = 1;
            }
        }
        /* this should follow 'rule-type' since it changes rule_flusing defaults set by rule-type */
        else if( strcmp(key,"rule-flushing")==0 )
        {
            if( !value )
                FatalError("metadata key '%s' requires a value\n",key);

            if(  strcmp(value,"enabled")==0 ||
                 strcmp(value,"on")==0 )
            {
                otn->sigInfo.rule_flushing= SI_RULE_FLUSHING_ON;
            }
            else if( strcmp(value,"disabled")==0 ||
                     strcmp(value,"off")==0 )
            {
                otn->sigInfo.rule_flushing = SI_RULE_FLUSHING_OFF;
            }
            else
            {
               /* error */
               FatalError("%s(%d)=> Metadata Key 'rule-type', passed an invalid value '%s'\n",
                    file_name, file_line, value);
            }
        }
        else if( strcmp(key,"rule-type")==0 )
        {
            if( !value )
                FatalError("metadata key '%s' requires a value\n",key);

            if( strcmp(value,"preproc")==0 )
            {
                otn->sigInfo.rule_type= SI_RULE_TYPE_PREPROC;
                otn->sigInfo.rule_flushing = SI_RULE_FLUSHING_OFF;
            }
            else if( strcmp(value,"decode")==0 )
            {
                otn->sigInfo.rule_type = SI_RULE_TYPE_DECODE;
                otn->sigInfo.rule_flushing = SI_RULE_FLUSHING_OFF;
            }
            else if( strcmp(value,"detect")==0 )
            {
                otn->sigInfo.rule_type = SI_RULE_TYPE_DETECT;
                otn->sigInfo.rule_flushing = SI_RULE_FLUSHING_ON;
            }
            else
            {
               /* error */
               FatalError("%s(%d)=> Metadata Key 'rule-type', passed an invalid value '%s'\n",
                    file_name, file_line, value);
            }
        }
        else if (strcmp(key, "soid")==0 )
        {
            if( !value )
                FatalError("metadata key '%s' requires a value\n",key);

            /* value is a : separated pair of gid:sid representing
             * the GID/SID of the original rule.  This is used when
             * the rule is duplicated rule by a user with different
             * IP/port info.
             */
            toks = mSplit(value, "|", 2, &num_toks, 0);
            if (num_toks != 2)
            {
                FatalError("%s(%d)=> Metadata Key '%s' Invalid Value."
                    "Must be a pipe (|) separated pair.\n",
                    file_name, file_line, key);
            }

            otn->sigInfo.otnKey.generator = strtoul(toks[0], &endPtr, 10);
            if( *endPtr )
                FatalError("Bogus gid %s",toks[0]);
            
            otn->sigInfo.otnKey.id = strtoul(toks[1], &endPtr, 10);
            if( *endPtr )
                FatalError("Bogus sid %s",toks[1]);

            mSplitFree(&toks, num_toks);
        }
#ifdef TARGET_BASED 
#ifdef PORTLISTS
        else if( strcmp(key,"service") == 0 ) /* track all of the rules for each service */
        {
            // metadata: service http, ... ;
            if( !value )
                FatalError("metadata key '%s' requires a value\n",key);
            otn->sigInfo.service = SnortStrdup(value);
            otn->sigInfo.service_ordinal = FindProtocolReference(otn->sigInfo.service);
            if (otn->sigInfo.service_ordinal == SFTARGET_UNKNOWN_PROTOCOL)
            {
                otn->sigInfo.service_ordinal = AddProtocolReference(otn->sigInfo.service);
            }
        }
        else if( strcmp(key,"os") == 0 ) /* track all of the rules for each os */
        {
            // metadata: os = Linux:w
            // 
            if( !value )
                FatalError("metadata key '%s' requires a value\n",key);
            otn->sigInfo.os = SnortStrdup(value);
        }
#endif
#endif
        else
        {
            //LogMessage("Ignoring Metadata : %s = %s \n",key,value);
        }
    }

    mSplitFree(&key_toks, num_keys);

    return;
}



void ParseClassType(char *classtype, OptTreeNode *otn)
{
    ClassType *classType;
    if(classtype != NULL)
    {
        while(isspace((int)*classtype)) 
            classtype++;

        if(strlen(classtype) > 0)
        {
            classType = ClassTypeLookupByType(classtype);
            if (classType)
            {
                otn->sigInfo.classType = classType;

                /*
                **  Add the class_id to class_id so we can
                **  reference it for all rules, whether they have
                **  a class_id or not.
                */
                otn->sigInfo.class_id = classType->id;
                
                if(otn->sigInfo.priority == 0)
                    otn->sigInfo.priority = classType->priority;
                /* deprecated */
                otn->event_data.classification = classType->id;
                if(otn->event_data.priority == 0)
                    otn->event_data.priority = classType->priority;
                return;
            }
        }
        FatalError("%s(%d) => Unknown ClassType: %s\n", file_name, 
                   file_line, classtype);
        return;
    }

    LogMessage("WARNING %s(%d) => ClassType without an argument!\n", file_name, 
               file_line);

    return;
}

ClassType *ClassTypeLookupByType(char *type)
{
    ClassType *idx = classTypes;
    if(!type)
        return NULL;

    while(idx)
    {
        if(strcasecmp(type, idx->type) == 0)
            return idx;
        idx = idx->next;
    }
    return NULL;
}

ClassType *ClassTypeLookupById(int id)
{
    ClassType *idx = classTypes;
    while(idx)
    {
        if(idx->id == id)
            return idx;
        idx = idx->next;
    }
    return NULL;
}


void ParseClassificationConfig(char *args)
{
    char **toks;
    int num_toks;
    char *data;
    ClassType *newNode;

    toks = mSplit(args, ",",3, &num_toks, '\\');

    if(num_toks != 3)
    {
        ErrorMessage("%s(%d): Invalid classification config: %s\n",
                     file_name, file_line, args);
    }
    else
    {
        /* create the new node */
        newNode = (ClassType *)SnortAlloc(sizeof(ClassType));

        data = toks[0];
        while(isspace((int)*data)) 
            data++;
        newNode->type = SnortStrdup(data);   /* XXX: oom check */

        data = toks[1];
        while(isspace((int)*data))
            data++;
        newNode->name = SnortStrdup(data);   /* XXX: oom check */

        data = toks[2];
        while(isspace((int)*data))
            data++;
        /* XXX: error checking needed */
        newNode->priority = atoi(data); /* XXX: oom check */

        if(AddClassificationConfig(newNode) == -1)
        {
            ErrorMessage("%s(%d): Duplicate classification \"%s\""
                    "found, ignoring this line\n", file_name, file_line, 
                    newNode->type);

            if(newNode)
            {
                if(newNode->name)
                    free(newNode->name);
                if(newNode->type)
                    free(newNode->type);
                free(newNode);
            }
        }
    }

    mSplitFree(&toks, num_toks);
    return;
}

int AddClassificationConfig(ClassType *newNode)
{
    int max_id = 0;
    ClassType *current;

    current = classTypes;

    while(current)
    {
        /* dup check */
        if(strcasecmp(current->type, newNode->type) == 0)
            return -1;
        
        if(current->id > max_id)
            max_id = current->id;
        
        current = current->next;
    }

    /* insert node */
    
    newNode->id = max_id + 1;
    newNode->next = classTypes;
    classTypes = newNode;

    return newNode->id;
}

        
OptTreeNode * soid_sg_otn_lookup( u_int32_t gid, u_int32_t sid )
{
    OptTreeNode * otn = NULL;
    sg_otn_key_t  key;

    key.generator=gid;
    key.id       =sid;
    soidOTN = otn = (OptTreeNode*) sfghash_find(soid_sg_otn_map,&key);
    return otn;
}

OptTreeNode * soid_sg_otn_lookup_next( u_int32_t gid, u_int32_t sid )
{
    OptTreeNode * otn = NULL;

    if (soidOTN)
    {
        otn = soidOTN->nextSoid;
        soidOTN = soidOTN->nextSoid;
    }

    return otn;
}

int soid_otn_lookup_init()
{
    if (!soid_sg_otn_map)
    {
        soid_sg_otn_map = sfghash_new(10000,sizeof(sg_otn_key_t),0,free);
        if (!soid_sg_otn_map)
            return -1;
    }
    return 0;
}

void soid_otn_lookup_add( OptTreeNode * otn_tmp )
{
    if (otn_tmp->sigInfo.otnKey.generator == 0)
    {
         otn_tmp->sigInfo.otnKey.generator= otn_tmp->sigInfo.generator;
         otn_tmp->sigInfo.otnKey.id = otn_tmp->sigInfo.id;
    }
    if (sfghash_add(soid_sg_otn_map,&(otn_tmp->sigInfo.otnKey),otn_tmp) == SFGHASH_INTABLE)
    {
         OptTreeNode *otn_original = soid_sg_otn_map->cnode->data;
         if (!otn_original)
         {
             /* */
             FatalError("Missing Duplicate\n");
         }
         while (otn_original->nextSoid)
         {
             otn_original = otn_original->nextSoid;
         }
         otn_original->nextSoid = otn_tmp;
    }
}

void otn_remove(OptTreeNode *otn) 
{
    sg_otn_key_t key;
    
    if(!otn) 
        return;

    key.generator = otn->sigInfo.generator; 
    key.id = otn->sigInfo.id;

    sfghash_remove(sg_rule_otn_map, &key);
    sfghash_remove(soid_sg_otn_map, &(otn->sigInfo.otnKey));
}

int otn_lookup_init()
{
    if (!sg_rule_otn_map)
    {
        sg_rule_otn_map = sfghash_new(10000,sizeof(sg_otn_key_t),0,NULL);
        if (!sg_rule_otn_map)
            return -1;
    }
    return 0;
}
void otn_lookup_add( OptTreeNode * otn )
{
    sg_otn_key_t key;
    
    key.generator = otn->sigInfo.generator;
    key.id = otn->sigInfo.id;

    sfghash_add(sg_rule_otn_map, &key, otn);
}

OptTreeNode * otn_lookup( u_int32_t gid, u_int32_t sid )
{
    OptTreeNode * otn;
    sg_otn_key_t  key;

    key.generator=gid;
    key.id       =sid;
    otn = (OptTreeNode*) sfghash_find(sg_rule_otn_map,&key);
    return otn;
}
        
/***************** End of Class/Priority Implementation ***********************/
