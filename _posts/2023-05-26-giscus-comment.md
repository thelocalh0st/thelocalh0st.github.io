---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://www.thebigredgroup.com/wp-content/uploads/2021/06/top-six.jpg"> Comment system with GISCUS
date: 2023-05-26 00:00:02 +730
categories: [Resources, general]
tags: [comment-system, jekyl,giscus] # TAG names should always be lowercase


---



# Add comment system to your static site with Giscus


## Problem

By default, you can't add a comment system to a static generated site unless you use a third party help. As a developer using GitHub API to give our personal site a comment system is something fun and sometimes useful to do.

## Solution

There are two different option that you can choose , it's either giscus or utterances, the difference is that giscus utilize GitHub discussion API, while utterances utilize GitHub issues

## Goal

In this post, I will share step-by-step how to utilize Giscus to give our Next.js site a comment system.

### Step 1: Enable GitHub discussion

1.  On GitHub.com, navigate to the main page of the repository.
2.  Under your repository name, click ⚙️ Settings.  
<img width="568" alt="select-settings" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/0d9dc68d-b9ef-4b0b-962d-a0863cfd06f2">

    
3.  Under "Features", click Set up discussions.  
    
4.  Under "Start a new discussion," edit the template to align with the resources and tone you want to set for your community.
    
5.  Click Start discussion.  
    <img width="484" alt="setup-discussion" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/8532c316-32f6-426f-a389-a8eec65cef16">

    

### Step 2: Enable Giscus

Head to  [https://github.com/apps/giscus](https://github.com/apps/giscus)  and enable giscus in your desired repository

### Step 3: Get your repository API key

You can access your GitHub details via GitHub GraphQL API , you can access it  [here](https://docs.github.com/en/graphql/overview/explorer)  and then login with your GitHub account.  

```js

query { 
  repository(owner: "thelocalh0st", name:"thelocalh0st.github.io"){
    id
    discussionCategories(first:10) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
}


```

Basically, we are just making a request via GraphQL query to GitHub API to fetch our repository id, and our list of ten first discussion categories and its details (id, and name). The result will be something like this.  

```json

{
  "data": {
    "repository": {
      "id": "R_kgDOGjYtbQ",
      "discussionCategories": {
        "edges": [
          {
            "node": {
              "id": "DIC_kwDOGjYtbc4CA_TR",
              "name": "Announcements"
            }
          },
          {
            "node": {
              "id": "DIC_kwDOGjYtbc4CA_TS",
              "name": "General"
            }
          },
          {
            "node": {
              "id": "DIC_kwDOGjYtbc4CA_TU",
              "name": "Ideas"
            }
          },
          {
            "node": {
              "id": "DIC_kwDOGjYtbc4CA_TT",
              "name": "Q&A"
            }
          },
          {
            "node": {
              "id": "DIC_kwDOGjYtbc4CA_TV",
              "name": "Show and tell"
            }
          }
        ]
      }
    }
  }
}


```

### Step 4: Install @giscus/react package

> yarn add @giscus/react  
> or  
> npm i @giscus/react

### Step 5: Import and use Giscus component

```javascript

import { Giscus } from "@giscus/react";

export default function Comment() {
  return (
    <Giscus
      repo="thelocalh0st/thelocalh0st.github.io"
      repoId="R_kgDOGjYtbQ"
      category="General"
      categoryId="DIC_kwDOGjYtbc4CA_TS"
      mapping="pathname"
      reactionsEnabled="0"
      emitMetadata="0"
      theme="dark"
    />
  );
}


```

<img width="555" alt="comment" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/7756f184-74aa-44ee-85b7-9607e9b6f50d">

It will render a GitHub comment widget where other developer can sign in using their GitHub account to comment through GitHub Discussion API.

That's it folks! Hope this tutorial help, and happy hacking!

**Reference:**

[https://giscus.app/](https://giscus.app/)  
[https://graphql.org/](https://graphql.org/)  
[https://www.freecodecamp.org/news/graphql-vs-rest-api/](https://www.freecodecamp.org/news/graphql-vs-rest-api/)
