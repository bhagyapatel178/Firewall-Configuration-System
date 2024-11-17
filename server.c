#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>


#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <string.h>

#define BUFFERLENGTH 256

/* displays error messages from system calls */
void error(char *msg) {
    perror(msg);
    exit(1);
}

//int is_in_interactive_mode = 0;
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for request linked list processing  */
pthread_mutex_t mut2 = PTHREAD_MUTEX_INITIALIZER; /* lock used for rules linked list*/



int writeResult (int sockfd, char *buffer, size_t bufsize) {
    int n;
   
    n = write(sockfd, &bufsize, sizeof(size_t));
    if (n < 0) {
		fprintf (stderr, "ERROR writing to result\n");
		return -1;
    }
    
    n = write(sockfd, buffer, bufsize);
    if (n != bufsize) {
		fprintf (stderr, "Couldn't write %ld bytes, wrote %d bytes\n", bufsize, n);
		return -1;
    }
    return 0;
}

char *readRes(int sockfd) {
    size_t bufsize;
    int res;
    char *buffer;

    res = read(sockfd, &bufsize, sizeof(size_t));
    if (res != sizeof(size_t)) {
		fprintf (stderr, "Reading number of bytes from socket failed\n");
		return NULL;
    }

    buffer = malloc(bufsize+1);
    if (buffer) {
		buffer[bufsize]  = '\0';
		res = read(sockfd, buffer, bufsize);
		if (res != bufsize) {
			fprintf (stderr, "Reading reply from socket\n");
			free(buffer);
			return NULL;
		}
    }
    
    return buffer;
}    

typedef struct RequestNode{
    char *request;
    struct RequestNode *next;
} RequestNode;

struct RequestNode *head = NULL;

char *list_requests(){
    pthread_mutex_lock(&mut);
    struct RequestNode *current = head;
    size_t total_length = 0;

    while(current != NULL){
        total_length +=strlen(current->request)+1;
        // printf("%s\n", current->request);
        current = current->next;
    }
    char *result = malloc(total_length +1);
    if(result == NULL){
        fprintf(stderr, "Memory allocation error\n");
        //free(result);
        return NULL;
    }
    current = head;
    size_t offset = 0;

    while (current != NULL){
        size_t request_len = strlen(current-> request);
        memcpy(result +offset, current->request, request_len);
        offset += request_len;

        result[offset] = '\n';
        offset++;

        current = current->next;
    }

    result[offset]= '\0';
    pthread_mutex_unlock(&mut);

    return result;
}

void add_request_to_list(char *buffer){
    pthread_mutex_lock(&mut);
    struct RequestNode *node;
    struct RequestNode *current;

    node = malloc(sizeof(struct RequestNode));
    if (node == NULL){
        printf("Cannot allocate memory, existing. \n");
        free(node);
        exit(1);
    }
    node ->request = strdup(buffer);
    if (node->request == NULL){
        printf("Cannot allocate memory for request, existing. \n");
        free (node);
        exit(1);
    }
    node ->next = NULL;

    if(head == NULL){
        head = node;
    }else {
        current = head;
        while(current->next != NULL){
            current = current->next;
        }
        current->next = node;
    }

    pthread_mutex_unlock(&mut);
    
}

typedef struct QueryNode {
    char *ip; 
    char *port;
    struct QueryNode *next;
} QueryNode;

typedef struct Rule {
    char *ip_segment; 
    char *port_segment;
    struct QueryNode *queries; 
    struct Rule *next;
} Rule;

//extern Rule *rule_head = NULL;

struct Rule *rule_head = NULL;

bool is_valid_ip(const char *ip){
    int segments = 0;
    int value;
    char *endptr;
    char *ip_saveptr;

    for(int i = 0; i < strlen(ip);i++){
        if(ip[i] == '.'){
            segments++;
        }
    }
    if(segments !=3)return false;

    char *ip_copy = strdup(ip);
    if (!ip_copy) return false;

    char *segment = strtok_r(ip_copy, "." , &ip_saveptr); //strtok_r
    while(segment){
        value = strtol(segment, &endptr,10);
        if(*endptr!= '\0'|| value < 0|| value > 255){
            free(ip_copy);
            return false;
        }
        segment = strtok_r(NULL, ".", &ip_saveptr);
    }
    

    free(ip_copy);
    return true;
}

bool is_ip_less_than(const char *ip, const char *ip2){
    int segments1[4], segments2[4];
    sscanf(ip, "%d.%d.%d.%d", &segments1[0],&segments1[1],&segments1[2],&segments1[3]);
    sscanf(ip2, "%d.%d.%d.%d", &segments2[0],&segments2[1],&segments2[2],&segments2[3]);

    for(int i=0;i< 4; i++){
        if (!(segments1[i]<= segments2[i])){
            return false;
        }
    }
    return true;
}

bool is_valid_ip_part(const char *ip_range){
    char *ip1, *ip2;
    char *saveptr;

    char *range_copy = strdup(ip_range);
    if(!range_copy){
        printf("Memory allocation failed\n");
        return false;
    }

    if (is_valid_ip(ip_range)){
        free(range_copy);
        return true;
    }

    ip1 = strtok_r(range_copy, "-", &saveptr);
    ip2 = strtok_r(NULL, "-", &saveptr );

    bool is_valid = (ip1 && ip2 && is_valid_ip(ip1) && is_valid_ip(ip2) && is_ip_less_than(ip1, ip2));
    free(range_copy);
    return is_valid;

}

bool is_valid_port_part(char *port_range){
    //int segments = 1;
    if (strchr(port_range, '-') == NULL){
        int port = atoi(port_range);
        return (port>=0 && port<= 65535);
    }

    char *range_copy = strdup(port_range); //duplicates port 23 or 23-50
    if(!range_copy){
        printf("Memory allocation failed\n");
        return false;
    }
    
    char *saveptr;
    char *port1_str = strtok_r(range_copy, "-", &saveptr);
    char *port2_str = strtok_r(NULL, "-", &saveptr);

    int port1 = port1_str ? atoi(port1_str):-1; 
    int port2 = port2_str ? atoi(port2_str):-1; 

    bool is_valid = (port1_str&& port2_str && port1>=0 && port1<=65535 && port2>0 && port2<=65535);

    free(range_copy);
    return is_valid;
}

char *add_rule(char *rule){
    char *saveptr;
    char *ip_section = NULL, *port_section = NULL;
    char *rule_copy = strdup(rule);

    //splits up ips and portsr
    ip_section = strtok_r(rule_copy, " ", &saveptr);
    port_section = strtok_r(NULL, " ", &saveptr);
    //checks both parts exist
    if (!ip_section|| !port_section){
        //printf("Invalid rule\n"); 
        free(rule_copy);
        return "Invalid rule\n"; 
    }

    if(!is_valid_ip_part(ip_section) || !is_valid_port_part(port_section)){
        //printf("Invalid rule\n");
        free(rule_copy);
        return "Invalid rule\n";
    }

    pthread_mutex_lock(&mut2);
    struct Rule *new_rule = malloc(sizeof(struct Rule ));
    if(!new_rule){
        printf("Failed to allocate memory for the rule\n");
        free(rule_copy);
        pthread_mutex_unlock(&mut2);
        return NULL;
    }

    new_rule -> ip_segment = strdup(ip_section);
    new_rule -> port_segment = strdup(port_section);
    new_rule -> queries = NULL;
    new_rule -> next = NULL;

    if (!rule_head){
        rule_head = new_rule;
    }else {
        struct Rule *current = rule_head;
        while (current->next){
            current = current->next;
        }
        current->next =new_rule;
    }
    free(rule_copy);
    pthread_mutex_unlock(&mut2);
    return "Rule added\n";
}

bool isSingleValue(const char *value){ //true if is single value ie secondbit is null, false if 2 bits
    char *value_copy = strdup(value);

    if (!value_copy){
        return false;
    }

    char *saveptr;
    char *firstBit = strtok_r(value_copy, "-", &saveptr);
    char *secondBit = strtok_r(NULL, "-", &saveptr);

    free(value_copy);

    return (firstBit!=NULL)  && (secondBit == NULL);
}

bool is_in_range(const char *ip, const char *range){

    if(isSingleValue(range)){
        if (strcmp(ip, range)== 0){
            return true;
        }
    }

    char *range_copy = strdup(range);
    char *value_check_copy = strdup(ip);
    if(!range_copy || !value_check_copy){
        free(range_copy);
        free(value_check_copy);
        return false;
    }

    char *saveptr;
    char *rangeLowerPart = strtok_r(range_copy, "-", &saveptr);
    char *rangeUpperPart = strtok_r(NULL, "-", &saveptr);

    if(!rangeLowerPart|| !rangeUpperPart){
        free(range_copy);
        free(value_check_copy);
        return false;
    }

    if(strchr(value_check_copy, '.')){
        int querySegment[4], smallerIp[4], largerIP[4];
        sscanf(value_check_copy, "%d.%d.%d.%d", &querySegment[0],&querySegment[1],&querySegment[2],&querySegment[3]);
        sscanf(rangeLowerPart, "%d.%d.%d.%d", &smallerIp[0],&smallerIp[1],&smallerIp[2],&smallerIp[3]);
        sscanf(rangeUpperPart, "%d.%d.%d.%d", &largerIP[0],&largerIP[1],&largerIP[2],&largerIP[3]);

        for(int i = 0; i < 4; i++){
            if((querySegment[i]< smallerIp[i]) || (querySegment[i]> largerIP[i])){
                free(range_copy);
                free(value_check_copy);
                return false; 
            }
        }
    }else{
        int value_check_rangeint = atoi(value_check_copy);
        int rangeLowerPartint = atoi(rangeLowerPart);
        int rangeUpperPartint = atoi(rangeUpperPart);

        if(value_check_rangeint < rangeLowerPartint || value_check_rangeint > rangeUpperPartint ){
            free(range_copy);
            free(value_check_copy);
            return false; 
        }
    }
    free(range_copy);
    free(value_check_copy);
    return true;

}

void add_query_to_rule(Rule *rule, const char *ip, const char *port){
    QueryNode *new_query = malloc(sizeof(QueryNode));
    new_query-> ip = strdup(ip);
    new_query-> port = strdup(port);
    new_query-> next = NULL;

    if(rule->queries == NULL){
        rule ->queries = new_query;
    }else{
        QueryNode *curr = rule->queries;
        while (curr->next != NULL){
            curr = curr-> next;
        }
        curr -> next = new_query;
    }
    
}

char *check_ip_and_port(char *ip_and_port){
    char *saveptr; 
    char *ip = strtok_r(ip_and_port," ", &saveptr);
    char *port_str = strtok_r(NULL, " ", &saveptr);

    // printf("ip=%s\n", ip);
    // printf("port=%s\n", port_str);


    if (!ip || ! port_str){
        // printf("Illegal IP address or port specified\n");
        return "Illegal IP address or port specified\n";
    }

    // printf("ip_valid=%d\n", is_valid_ip(ip));
    // printf("port_valid=%d\n", is_valid_port_part(port_str));

    if (!is_valid_ip(ip) || !is_valid_port_part(port_str)){
    
        //printf("Illegal IP address or port specified\n");
        return "Illegal IP address or port specified\n"; 
    }

    pthread_mutex_lock(&mut2);
    // int *port = atoi(port_str);
    Rule *current_rule = rule_head;
    //bool complies = false;

    while(current_rule){
        // printf("ip: %s port:%s", current_rule->ip_segment, current_rule-> port_segment);
        // printf("is_in_range(ip, current_rule->ip_segment) = %d\n", is_in_range(ip, current_rule->ip_segment));
        // printf("is_in_range(port_str, current_rule->port_segment) = %d\n", is_in_range(port_str, current_rule->port_segment));
        
        if (is_in_range(ip, current_rule-> ip_segment)&& is_in_range(port_str, current_rule->port_segment)){
            add_query_to_rule(current_rule, ip, port_str);
            //printf("Connect accepted\n");
            //complies = true;
            pthread_mutex_unlock(&mut2);
            return "Connect accepted\n";
        }
        current_rule = current_rule-> next;
    }
    pthread_mutex_unlock(&mut2);
    return "Connection rejected\n";
}

char *delete_rule(char *rule){
    // !!!!!!!!!!!!Enter a command: A 1.1.1.1 1234
    // Rule added
    // Enter a command: D 1.1.1.1 1234
    // Rule deleted
    // Enter a command: A 1.1.1.1 123
    // Rule added
    // Enter a command: D 001.1.1.1 123 
    // Rule not found
    // Enter a command: 

    char *saveptr; 
    char *rule_copy = strdup(rule);
    char *ip_section = strtok_r(rule_copy," ", &saveptr);
    char *port_section = strtok_r(NULL, " ", &saveptr);

    //checks both parts exist
    if (!ip_section|| !port_section ||!is_valid_ip_part(ip_section) || !is_valid_port_part(port_section)){
        //printf("Rule invalid\n"); 
        free(rule_copy);
        return "Rule invalid\n"; 
    }

    pthread_mutex_lock(&mut2);

    if (!rule_head){
        // printf("Rule not found\n");
        free(rule_copy);
        pthread_mutex_unlock(&mut2);
        return "Rule not found\n";
    }

    
    struct Rule *current = rule_head;
    // printf("%s", current-> ip_segment);
    struct Rule *prev = NULL;

    if(strcmp(ip_section, current->ip_segment)==0 && strcmp(port_section, current -> port_segment)==0){
        rule_head = current -> next;
        free(current->ip_segment);
        free(current->port_segment);

        if(current->queries){
            struct QueryNode *query_current = current-> queries;
            while(query_current != NULL){
                struct QueryNode *query_next = query_current->next;

                free(query_current->ip); 
                free(query_current->port); // Example: Replace with the actual query field name
                free(query_current);

                query_current = query_next;
            }
        }
         
        free(current);
        //printf("Rule deleted\n");
        free(rule_copy);
        pthread_mutex_unlock(&mut2);
        return "Rule deleted\n";
    }

    while (current != NULL){
        if (strcmp(ip_section, current->ip_segment)==0 && strcmp(port_section, current -> port_segment)==0){
                
            prev->next = current->next;
            free(current->ip_segment);
            free(current->port_segment);

            if(current->queries){
                struct QueryNode *query_current = current->queries;
                while(query_current != NULL){
                    struct QueryNode *query_next = query_current->next;
            
                    // Assuming each query node needs to be freed, including any dynamically allocated fields.
                    free(query_current->ip); 
                    free(query_current->port); // Example: Replace with the actual query field name
                    free(query_current);

                    query_current = query_next;
                }
            }
            free(current);
            //printf("Rule deleted\n");
            free(rule_copy);
            pthread_mutex_unlock(&mut2);
            return "Rule deleted\n";
        }

        prev = current;
        //free(prev);
        current = current->next;
        //free(prev);
        
    }
    //printf("Rule not found\n");
    free(rule_copy);
    pthread_mutex_unlock(&mut2);
    return "Rule not found\n"; 

}

char *return_all_rules(){
    //fill
    pthread_mutex_lock(&mut2);
    struct Rule *current = rule_head;
    size_t total_length = 0;

    while(current != NULL){
        total_length+= strlen(current->ip_segment) + strlen(current->port_segment) + 10;
        //printf("Rule: %s %s\n", current->ip_segment, current->port_segment);
        QueryNode *curQuery = current->queries;
        while(curQuery != NULL){
            total_length+= strlen(curQuery->ip) + strlen(curQuery->port) + 10;
            //printf("Query: %s %s\n", curQuery->ip, curQuery->port);
            curQuery = curQuery -> next;
        }
        current = current->next;
    }

    char *result = malloc(total_length +1);
    if (result == NULL){
        pthread_mutex_unlock(&mut2);
        return NULL;
    }
    current = rule_head;
    size_t offset = 0;

    while (current != NULL){
        offset += snprintf(result + offset, total_length - offset, "Rule: %s %s\n", current -> ip_segment, current-> port_segment);

        QueryNode *curQuery = current-> queries;
        while (curQuery != NULL){
            offset += snprintf(result + offset, total_length - offset, "Query: %s %s\n", curQuery->ip, curQuery->port);
            curQuery = curQuery-> next;
        }
        current = current -> next;
    }
    
    result[offset] = '\0';
    pthread_mutex_unlock(&mut2);
    return result;
}

void interactive_mode(){
    char *buffer = NULL;
    size_t buffer_size = 0; 
    ssize_t input_length;
    while (1){
        //printf("Enter a command: ");

        input_length = getline(&buffer, &buffer_size, stdin); //fgets instead of getline 

        if(input_length == -1){
            if(feof(stdin)){
                break;
            }
            continue;
        }else{
            if (buffer[input_length -1] == '\n'){
                buffer[input_length-1] = '\0';
            }

            char *response = NULL;

            if (buffer[0] == 'R' && buffer[1] == '\0'){
                response = list_requests();
            }
            else if(buffer[0] == 'A' && buffer[1] == ' '){
                char *rule = buffer +2;
                response = add_rule(rule);
            }
            else if(buffer[0] == 'C' && buffer[1] == ' '){
                char *ip_and_port = buffer +2;
                response = check_ip_and_port(ip_and_port);
            }
            else if(buffer[0] == 'D' && buffer[1] == ' '){
                char *rule = buffer +2;
                response = delete_rule(rule);
            }
            else if (buffer[0] == 'L' && buffer[1] == '\0'){
                response = return_all_rules();
            }
            else{
                response = "Illegal request\n";
            }

            if(response){
                printf("%s", response);
                if ((buffer[0] == 'R' && buffer[1] == '\0') || (buffer[0] == 'L' && buffer[1] == '\0')){
                    free(response);
                }
                //free(response);
            }
            
            //need to create a function to add the request to list
            add_request_to_list(buffer);
        }
    }
    free(buffer);

}

void free_request_list(){
    struct RequestNode *current = head;
    struct RequestNode *temp;

    while(current !=NULL){
        temp = current;
        current = current->next;
        free(temp->request);
        free(temp);
    }
    head =NULL;

}

void free_rule_list(){
    struct Rule *current_rule = rule_head;
    struct Rule *temp_rule;

    while(current_rule !=NULL){
        temp_rule = current_rule;
        current_rule = current_rule->next;
        QueryNode *curQuer = temp_rule->queries;
        QueryNode *temp_query;

        while(curQuer !=NULL){
            temp_query = curQuer;
            curQuer= curQuer->next;
            free(temp_query->ip);
            free(temp_query-> port);
            free(temp_query);
        }
        free(temp_rule->ip_segment);
        free(temp_rule->port_segment);
        free(temp_rule);
    }
    head =NULL;

}

/* For each connection, this function is called in a separate thread. */
void *processRequest (void *args) {
    int *newsockfd =  (int *) args;
    char *buffer = readRes (*newsockfd);

    if (!buffer)  {
		fprintf (stderr, "ERROR reading from socket\n");
        close(*newsockfd); /* important to avoid memory leak */
        free (newsockfd);
        pthread_exit (NULL); /*exit value not used */
    }
    char *response = NULL;

    if (buffer[0] == 'R' && buffer[1] == '\0'){
        response = list_requests();
    }
    else if(buffer[0] == 'A' && buffer[1] == ' '){
        char *rule = buffer +2;
        response = add_rule(rule);
    }
    else if(buffer[0] == 'C' && buffer[1] == ' '){
        char *ip_and_port = buffer +2;
        response = check_ip_and_port(ip_and_port);
    }
    else if(buffer[0] == 'D' && buffer[1] == ' '){
        char *rule = buffer +2;
        response = delete_rule(rule);
    }
    else if (buffer[0] == 'L' && buffer[1] == '\0'){
        response = return_all_rules();
    }
    else{
        response = "Illegal request\n";
    }

    if(response){
        writeResult(*newsockfd, response, strlen(response)+1);

        if ((buffer[0] == 'R' && buffer[1] == '\0') || (buffer[0] == 'L' && buffer[1] == '\0')){
            free(response);
        }
        // free(response);
    }
    add_request_to_list(buffer);

    free(buffer);
    close(*newsockfd);
    free(newsockfd);
    pthread_exit (NULL); /*exit value not used */

}

//     {
// 		// printf ("Here is the message: %s\n",buffer);
// 		pthread_mutex_lock (&mut); /* lock exclusive access to variable isExecuted */
// 		tmp = isExecuted;
			
// 		printf ("Waiting for confirmation: Please input an integer\n");
// 		scanf ("%d", &n); /* not to be done in real programs: don't go to sleep while holding a lock! Done here to demonstrate the mutual exclusion problem. */
// 		printf ("Read value %d\n", n);

// 		isExecuted = tmp +1;
// 		pthread_mutex_unlock (&mut); /* release the lock */
		
// 		buffer = realloc(buffer, BUFFERLENGTH);
// 		n = sprintf (buffer, "I got you message, the value of isExecuted is %d\n", isExecuted);
// 		/* send the reply back */
// 		n = writeResult (*newsockfd, buffer, strlen(buffer) + 1);
// 		if (n < 0) {
// 			fprintf (stderr, "Error writing to socket\n");
// 		}
//     }
    
//     free(buffer);
//     close(*newsockfd); /* important to avoid memory leak */
//     free (newsockfd);
	  
//     pthread_exit (NULL); /*exit value not used */
// }



int main (int argc, char ** argv) {
    /* to be written */

    int sockfd, portno;
    struct sockaddr_in6 serv_addr;
    int result;

    if (argc < 2) {
		fprintf (stderr,"ERROR, no port provided\n");
		exit(1);
    }

    if(strcmp(argv[1], "-i") == 0){
        //is_in_interactive_mode = 1;
        interactive_mode();
        return 0;
    }
	     
    /* create socket */
    sockfd = socket (AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) 
	error("ERROR opening socket");
    bzero ((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons (portno);

    /* bind it */
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		error("ERROR on binding");
	}

    /* ready to accept connections */
    listen (sockfd,5);

    /* now wait in an endless loop for connections and process them */
    while(1) {
		pthread_t server_thread; /* thread information */
		pthread_attr_t pthread_attr; /* attributes for newly created thread */
		int *newsockfd;
		struct sockaddr_in6 cli_addr;
		socklen_t clilen;

		clilen = sizeof(cli_addr);
		newsockfd  = malloc(sizeof (int));
		if (!newsockfd) {
			fprintf (stderr, "Memory allocation failed!\n");
			exit(1);
		}
		
		/* waiting for connections */
		*newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if (*newsockfd < 0) {
            free(newsockfd);
			error ("ERROR on accept");
		}

		/* create thread for processing of connection */
		if (pthread_attr_init (&pthread_attr)) {
			fprintf (stderr, "Creating initial thread attributes failed!\n");
            free(newsockfd);
			exit (1);
		}

		if (pthread_attr_setdetachstate (&pthread_attr, PTHREAD_CREATE_DETACHED)) {
			fprintf (stderr, "setting thread attributes failed!\n");
            free(newsockfd);
			exit (1);
		}
			
		result = pthread_create (&server_thread, &pthread_attr, processRequest, (void *) newsockfd);
        //pthread_attr_destroy(&pthread_attr);
		if (result != 0) {
			fprintf (stderr, "Thread creation failed!\n");
            free(newsockfd);
			exit (1);
		}
    }
    free_request_list();
    free_rule_list();

    return 0;
}