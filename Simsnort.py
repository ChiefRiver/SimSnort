#!/usr/bin/env python

# Import modules used here -- sys is a very standard on
import sys
import argparse
import subprocess

#take in commandline arguments
parser = argparse.ArgumentParser(description='This is a Snort rule creator by gsims')
parser.add_argument('-s', '--sources', help='Input file of Source IPs, seperated by newlines', required=False)
parser.add_argument('-d', '--destinations', help='Input file of Destination IPs, seperated by newlines', required=False)
args = parser.parse_args()

#print ("source file: %s" % args.sources )
#print ("destination file: %s" % args.destinations )


#prints out programs initial ASCII Art, whats my first python program without ascii art!
def GS_ascii():
	GS_art = """
         ******   ********    **    **      ******     ******        ****      ********    *************
        *            *       *  *  *  *    *          *      *     *      *    *       *         *
        *            *      *    **    *   *         *        *   *        *   *       *         *
         ****        *      *          *    ****     *        *   *        *   ********          *
             *       *      *          *        *    *        *   *        *   *       *         *
             *       *      *          *        *    *        *    *      *    *        *        *
       ******     ********  *          *  ******     *        *      ****      *         *       *
	
	
	"""
	print GS_art

#takes file and parses them into source addresses for rule
def source_or_dest_add_file(source_or_dest):
	all_sources_or_dests = ''
	if source_or_dest == 'sources':
	    sources_or_dest_file = open(args.sources)
	if source_or_dest == 'destinations':
	    sources_or_dest_file = open(args.destinations)
	source_or_dest_lines = sources_or_dest_file.readlines()
	for line in source_or_dest_lines:
		#print 'lines in file ', line.rstrip('\n')
		all_sources_or_dests += line.rstrip('\n') + ','
	all_sources_or_dests = all_sources_or_dests[:-1]
	#print 'all sources or dest ' , all_sources_or_dests
	return all_sources_or_dests

def add_to_SO_localrules(finalrule, comment):
	
	with open('/etc/nsm/rules/local.rules', 'a') as file:
		file.write('\n\n#'+comment)
		file.write('\n'+finalrule)
	
	rule_update_yn = raw_input('\nWould you like to run "rule-update" at this time to let your new rule go into affect? ')
	if rule_update_yn == 'y':
	    print subprocess.Popen("rule-update", shell=True, stdout=subprocess.PIPE).stdout.read()
	else:
		print 'You will need to run rule-update at a later time for your new rule to go int affect'
	

	
#allows input of str for depth modifier 
def modifier_depth():
	depth_str = raw_input('Enter the Depth that snort shall look your previouse content match (ex. 4 = only look 4 bytes into the payload) ')
	return depth_str
	
#allows input of str for offset modifier 
def modifier_offset():
	offset_str = raw_input('Enter the offset that snort shall START looking for your previouse content match (ex. 4 = Start looking 4 bytes into the payload) ')
	offset_list = []
	offset_list.append(offset_str)
	
	with_depth_yn = raw_input('would you like to use depth in conjuction with your offset? ')
	if with_depth_yn == 'y':
		depth_str = modifier_depth()
		offset_list.append(depth_str)
		#print 'offset_list ', offset_list
		#print 'offset_list Length ', len(offset_list)
	return offset_list
	
#allows input of str for distance modifier 
def modifier_distance():
	distance_str = raw_input('Enter the distance that snort shall START looking for your previouse content match relitive to last content match (ex. 4 = Skip 4 bytes from last content match then start looking) ')
	return distance_str
	
#allows input of str for within modifier 
def modifier_within():
	within_str = raw_input('Enter the within that snort shall look for content relitive to your previouse content match (ex. 4 = only look into the 4 bytes past last content match) ')
	return within_str



#allows the creation of mulitipule content matches
def snort_content():
	
	#Define Variables
	more_content = 'y'
	final_contents = ''
	i=0
	j=0
	selected_content_and_modifier_list = []
	content_array = []
	content = raw_input('Enter the content you wish to match on ')
	content_array.append(content)
	
	#if a modifier for the previouse conent is selected it will call the modifier function
	content_modifier_yn = raw_input('Would you like to add a modifier to this content match? (y/n) ')
	if content_modifier_yn in ['y']:
		selected_content_and_modifier_list = content_modifier(content)
	
	
	#run through loop to get more content matches if needed	
	while more_content in ['y']:
	    more_content = raw_input('Would you like to add another content match? (y/n) ')
	    if more_content in ['y']:
		    content2 = raw_input('Enter the content you wish to match on ')
		    content_array.append(content2)
		    
		    #if a modifier for the previouse conent is selected it will call the modifier function
		    content_modifier_yn = raw_input('Would you like to add a modifier to this content match? (y/n) ')
		    if content_modifier_yn in ['y']:
				
				#calls the modifier function and returns connent w/ the modifier
				content_w_modifier = content_modifier(content2)
				#content and modifier split into two object
				content1 = content_w_modifier[0]
				modifier1 = content_w_modifier[1]
				#new content added to content and modifer list
				selected_content_and_modifier_list.append(content1)
				#new modifier added to content and modifier list
				selected_content_and_modifier_list.append(modifier1)
				
				#print 'Contents with modifiers ', selected_content_and_modifier_list
				#print 'Just all Contents ', content_array
	
	#concat all the different contents into the correct format
	#also looks to see if content matches have modifiers and adds them too    
	while i<len(content_array):
		#print 'i2 ', i
		#print 'content_array length ', len(content_array)
		#print 'j ', j
		#print 'selected_content_and_modifier_list ', selected_content_and_modifier_list
		#print 'selected_content_and_modifier_list', len(selected_content_and_modifier_list)
		
		#if statement, if no modifier is selected for the only conntent match
		if len(selected_content_and_modifier_list) == 0:
			content_str = content_array[i]
			final_contents += 'content:"{elem}"; '.format(elem=content_str)
			#print 'final_contentssss', final_contents
			return final_contents
		
		#if statment, if last conntent added does NOT have a modifier	
		if j==len(selected_content_and_modifier_list):
			content_str = content_array[i]
			final_contents += 'content:"{elem}"; '.format(elem=content_str)
			print 'final_contentssss', final_contents
			return final_contents
			
		while j<len(selected_content_and_modifier_list):
			content_str = content_array[i]
			#print 'content_array', content_array
			#print 'content_str', content_str
			#print 'length ', len(selected_content_and_modifier_list)
			#print 'j ', j
			#print 'selected_contetnt_and_modifier_list', selected_content_and_modifier_list
			if selected_content_and_modifier_list[j] in content_str:
				modifier_string = selected_content_and_modifier_list[j+1]
				#print content_array[i], ' has a modifier'
				j=j+2
				final_contents += 'content:"{elem1}"; {elem2}; '.format(elem1=content_str, elem2=modifier_string)
				#print 'final contents1 ', final_contents
			else:
				final_contents += 'content:"{elem}"; '.format(elem=content_str)
				#print 'final_contents', final_contents
			i=i+1
			#print 'i ', i
			
	#return the formated contents for the alert	
	return final_contents


#allows the selection of class-type for the created rule
def class_type():
	
	#define variables
	i=1
	
	#defined snort rule classes
	snort_classes = {
		1: 'attempted-admin',
		2: 'attempted-user',
		3: 'inappropriate-content',
		4: 'policy-violation',
		5: 'shellcode-detect',
		6: 'successful-admin',
		7: 'successful-user',
		8: 'trojan-activity',
		9: 'unsuccessful-user',
		10: 'web-application-attack',
		}

	
	#list dictionary of class types
	print '\nPlease select one of the following Class Types for your rule'
	
	#while loop to list snort rule classes
	for key in snort_classes:
		print key, ' = ', snort_classes[key]
		key+1
		

	#get user to select snort rule class
	class_selected = raw_input()
	class_selected_int = int(class_selected)
	
	#print which class was selected and return that class
	print '\nClass Selected = ', snort_classes[class_selected_int], '\n'
	return snort_classes[class_selected_int]
	
#function to allow the addition of content modifiers
def content_modifier(content_w_modifier):
	
	#define variables
	content_and_modifier_list = []
	
	#list out all content modifiers
	content_modifier_list = {
		1: 'nocase',
		2: 'rawbytes',
		3: 'depth',
		4: 'offset',
		5: 'distance',
		6: 'within',
		7: 'http_client_body',
		8: 'http_cookie',
		9: 'http_raw_cookie',
		10: 'http_raw_header',
		11: 'http_method',
		12: 'http_uri',
		13: 'http_raw_uri',
		14: 'http_stat_code',
		15: 'http_stat_msg',
		16: 'fast_pattern',
		}
		
	#list dictionary of conent modifier types
	print '\nPlease select one of the following Modifiers for your content match '
	
	#while loop to list content modifier types
	for key in content_modifier_list:
		print key, ' = ', content_modifier_list[key]
		key+1
	
	#get user to select snort rule class
	modifier_selected = raw_input()
	modifier_selected_int = int(modifier_selected)
	
	#print which class was selected
	print 'Content modifier Selected = ', content_modifier_list[modifier_selected_int], '\n'
	just_modifier = content_modifier_list[modifier_selected_int]
	
	#runs functions for modifiers that require input
	if modifier_selected_int == 3:
		modifier_depth_str = modifier_depth()
		just_modifier = "".join([just_modifier, ':', modifier_depth_str])
		#print 'just modifier ', just_modifier
	
	if modifier_selected_int == 4:
		modifier_offset_list = modifier_offset()
		#print 'Modifier_offset_list ', modifier_offset_list
		#print 'Modifier_offset_list Length ', len(modifier_offset_list)
		
		#if used without depth
		if len(modifier_offset_list) == 1:
			modifier_offset_only = modifier_offset_list[0]
			just_modifier = "".join([just_modifier, ':', modifier_offset_only])
			#print 'just modifier ', just_modifier
			
		#if used in conjuction with depth	
		if len(modifier_offset_list) != 1:
			a = modifier_offset_list[0]
			b = modifier_offset_list[1]
			just_modifier = "".join([just_modifier, ':', a, '; depth:', b])
			#print 'with depth ', modifier_offset_list
		
	if modifier_selected_int == 5:
		modifier_distance_str = modifier_distance()
		just_modifier = "".join([just_modifier, ':', modifier_distance_str])
		#print 'just modifier ', just_modifier
		
	if modifier_selected_int == 6:
		modifier_within_str = modifier_within()
		just_modifier = "".join([just_modifier, ':', modifier_within_str])
		#print 'just modifier ', just_modifier
	
	#append Content that was inputed into function with modifier selected
	content_and_modifier_list.append(content_w_modifier)
	content_and_modifier_list.append(just_modifier)
	#print 'Current content with modifer ', content_and_modifier_list
	return content_and_modifier_list
	

#main function that starts basic question for rule creation
def main():
	#print ascii art to start program
    GS_ascii()
	
    protocol = raw_input('Snort rule protocol? (ex. tcp, udp or ip) ') 
    
    #see if source address where passed in as an argument
    if args.sources == None:
        source_add = raw_input('Snort rule source Address (ex. 192.168.1.1,192.168.1.0/24 $HOME_NET...) ')
    else: 
	    print 'You listed a source address file of ', args.sources
	    source_add = source_or_dest_add_file('sources')
	    source_add = '[' + source_add + ']'
        
    source_port = raw_input('Snort rule source port (ex. 80, !80, any...) ')
    
     #see if Destination address where passed in as an argument
    if args.destinations == None:
        dest_add = raw_input('Snort rule destination Address (ex. 192.168.1.1,192.168.1.0/24 $HOME_NET...) ')
    else: 
	    print ' You listed a Destination address file of ', args.destinations
	    dest_add = source_or_dest_add_file('destinations')
	    dest_add = '[' + dest_add + ']'
    
    dest_port = raw_input('Snort rule destination port (ex. 80, !80, any...) ')
    rule_message = raw_input('Snort rule message (ex. GPL SHELLCODE x86 inc ebx NOOP) ')
    content_yn = raw_input('would you like to add content to match on? (y/n) ')
    
    #selects whether or not the rule will include content match(es)
    if content_yn in ['y']:
        contents = snort_content()
    else:
		contents = ''
    
    #selects the class type for the rule  
    snort_class = class_type()
    
    #select sid for the rule
    snort_sid = raw_input('Enter Snort rule sid (ex 90000015) ')

	#prints the final rule
    print ''
    print 'Created Rule:'
    finalrule = "".join(['alert ', protocol, " ", source_add, " ", source_port,' -> ', dest_add," ", dest_port, ' (msg:"', rule_message, '";', " ", contents, 'classtype:', snort_class, '; sid:', snort_sid, '; rev:1;)'])
    print "".join(['alert ', protocol, " ", source_add, " ", source_port,' -> ', dest_add," ", dest_port, ' (msg:"', rule_message, '";', " ", contents, 'classtype:', snort_class, '; sid:', snort_sid, '; rev:1;)'])
    print ''
    
    addtolocalrules_yn = raw_input('would you like to add the rule above to the default local.rules location for SecurityOnion? (y/n) ')
    
    #selects whether or not the user wants the rule added to /etc/nsm/rules/local.rules
    if addtolocalrules_yn in ['y']:
        SOrule_comment = raw_input('\nPlease enter a comment you would like to add for your new rule (ex. This will alert on ICMP message sent from Host A) \n')
        add_to_SO_localrules(finalrule, SOrule_comment)
    else:
		print 'Thanks for using this program to create your snort rule!'
    
#call to start the main function of creating a snort rule!    
main()



