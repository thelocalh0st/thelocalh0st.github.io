---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://tryhackme-images.s3.amazonaws.com/room-icons/59bb6a64228a88219c0a9de1928226b8.jpeg">Giolocating Images
date: 2020-10-18 00:00:02 +730
categories: [Write Up, TryHackMe]
comments: true
tags: [tryhackme, giolocatingimages, osint] # TAG names should always be lowercase


---
![](https://miro.medium.com/v2/resize:fit:1176/1*BlY5AHXEk3iuPMf8uc23iQ.png)


# Task 1: Getting Started

main point:  [Yandex](https://yandex.com/),  [Bing](https://www.bing.com/)  then  [Google](https://www.google.com/)  for reverse image searching

Just for extra notes, there are browser extensions that you can download to speed up your process reverse image searching:

1.  [Fake news debunker by InVID & WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/)  (available on chrome and firefox only)
2.  RevEye Reverse Image search extension (available on  [chrome](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/keaaclcjhehbbapnphnmpiklalfhelgf?hl=en),  [firefox](https://addons.mozilla.org/en-US/firefox/addon/reveye-ris/)  and  [microsoft edge](https://microsoftedge.microsoft.com/addons/detail/reveye-reverse-image-sear/pgckeggiepakpomkmfpcmipmmodjmoal))

I think I will link these 2 articles to get the feel on how to use em:

1.  [https://datasociety.net/wp-content/uploads/2020/03/How-To-Verify-Online-Census-Media-final.pdf](https://datasociety.net/wp-content/uploads/2020/03/How-To-Verify-Online-Census-Media-final.pdf)
2.  [https://citizenevidence.org/2019/12/11/how-to-use-invid-the-swiss-army-knife-of-digital-verification/](https://citizenevidence.org/2019/12/11/how-to-use-invid-the-swiss-army-knife-of-digital-verification/)

# Task 2: Getting our feet wet — where is this?

**_The Question: Where in the world is image 1? The answer is the country name._**

The task asks to locate where is the nation of Image 1 located(you actually supposed to download a file from the previous task, just open the “thm” file and find 1.jpeg)

![](https://miro.medium.com/v2/resize:fit:840/1*_y2SfqKOC95dEPuTFJEvRA.jpeg)

this is the 1.jpeg

In this task, we need to use Yandex, Google, Bing and Tineye to figure out this image location (if you somehow upload this picture online, you can use the RevEye extension but in this case, I just upload the image to all 4 of the search engine)

![](https://miro.medium.com/v2/resize:fit:1176/1*3ppA_2ncIQ3g19Z1TBqF9w.png)

(Result 1: Google) pretty damn bad in my opinion because it just query out a shape instead of a monument.

![](https://miro.medium.com/v2/resize:fit:1176/1*05THam1XlXgT00yXgCwefg.png)

(Result 2: Yandex) finally we have a monument. The one that I highlight here is the answer of this task which is China.

![](https://miro.medium.com/v2/resize:fit:1176/1*C1PgfWOviW_Y1wbP4oPtBA.png)

(Result 3: Bing) It falls under the monument category but there are 2 major location here which is Chicago Bean, IL, US and Xinjiang, China. Better then Google but for this case but not good enough

![](https://miro.medium.com/v2/resize:fit:1176/1*nfHCH2zTPKaN6aEDG0LoKw.png)

(Result 4: TinEye) Well, there’s none.

Based on our result here, the information on the location of the monument is in China only found by Yandex because it is based in Russia compared to Google and Bing(US).

It is kinda well known that Google ban China for using their services. Here is the link that state all of the domain blocked by China for reference:

[](https://en.wikipedia.org/wiki/List_of_websites_blocked_in_mainland_China?oldformat=true&source=post_page-----ee818969139--------------------------------)

## List of websites blocked in mainland China - Wikipedia

### Many domain names are blocked in the People's Republic of China (mainland China) under the country's Internet…

en.wikipedia.org

So, Google won’t be your best bet when search anything China related.

Bing on the other hand is not blocked there

![](https://miro.medium.com/v2/resize:fit:1176/1*ldcmNeU5naArbI4XFi3PjQ.png)

The table that’s available on the Wiki article above. As you can see, it is unblocked.

So,Bing to some extent have the info on the monument but not as direct as Yandex but to be fair, the monument in 1.jpeg looks really similar to the Chicago Bean monument

> Conclusion that can be drawn here: Yandex is your best bet here to search stuff that is China related (make sure that you standby some sort of translator since Yandex query result mainly in Cyrillic because it is a Russian search engine)

**_The Answer: China_**

# Task 3: Geolocating Images 101

just a walkthough on how to geolocate a webcam image(if you use reverse image search in this type of image, you won’t get nothing)

> General flowchart to Geolocate Image from this task:
> 
> 1) Look for small identifier on the webcam image (anything really like badges, road sign or anything that can identify the location of the image)
> 
> 2) See if there’s any ip address or url linked to the webcam image
> 
> - If there’s ip address, use Shodan to find ASN number
> 
> - If there’s url, just open the url
> 
> - If there are no ip/url, just link together the identifer and try googling em’
> 
> 3) Open google maps and try to locate the image
> 
> 4) You’re done

# Task 4: Now your turn

**_The Question: Where was image 2 taken?_**

![](https://miro.medium.com/v2/resize:fit:1176/1*M2tm51EorufLw3UsCwpthg.png)

This is the 2.png.

Let us run through the general flow above to locate the this image:

1.  Look for small identifier on the webcam image

-   Green road sign with N and W together (Referring GeoTips.net, this is US)

![](https://miro.medium.com/v2/resize:fit:1176/1*bOotDFrBBDxnPKsTPtqgLw.png)

In  [https://geotips.net/north-america/](https://geotips.net/north-america/), you go to the US section and you’ll found this

-   A blue sign with “sports corner”
-   Not in UK because the license plate does not have the blue bar on the license plate

![](https://miro.medium.com/v2/resize:fit:672/0*j3eh1N3cCkGBzs48.png)

The UK license plate (generally EU have the blue bar in the left plus in this case, only UK have English as the official language)

2) See if there’s any ip address or url linked to the webcam image

So, in this picture there are no ip address and url linked with it.

We need to link the identifier together and google around.

From 1), basically we are somehow in Sports Center in US that located around Sheffield/Addison

From Googling, Addison is from Illonois (Sheffield will output a town with similar town in Alabama

![](https://miro.medium.com/v2/resize:fit:993/1*jpQgArgW2ifqRdf3FVLRVA.png)

Literally the first link searching Addison USA

Now Googling the Sports Corner il usa, you got a lot of choices of place.

2nd location in the search when we zoom the map, we got roughly the same location of the webcam.

![](https://miro.medium.com/v2/resize:fit:1176/1*l-8phhcCWkId6_ApB7Swhw.png)

So, as you can see here we have Addison and Sheffield together with the Sports Corner together. The answer here is Wrigleyville Sports

3) Open google maps and try to locate the image

![](https://miro.medium.com/v2/resize:fit:1079/1*K2cufss1J3oqsUSzyfQwxg.png)

It is really low res but you can roughly see the location of the shot.

**_The Answer: Wrigleyville Sports_**

# Task 4: Helpful tips for geolocating

> Tips given:  
> 1) See small indicator while geolocate
> 
> - Religious building like Mosque, Temple, Catholic to guess the main religion of the location
> 
> - Language used on shops and vehicles (use Google translate)
> 
> - Side of the road the car driving
> 
> - The license plate(accidentally used em’ above)
> 
> - The markings of the road (every country have different markings)
> 
> - The style of traffic lights
> 
> - Clothing of the people walking around
> 
> 2) check is there any EXIF data
> 
> 3) Is there any location tagged to the image

# Task 5: Your turn, again!

**_The Question: Where was image 3 taken?_**

![](https://miro.medium.com/v2/resize:fit:1176/1*Ud6FjHYdRRoYzaMBZdyJTg.png)

This 3.png that we will geolocate in this task

Let us use the general flow in Task 3 to solve this problem:

1.  Look for small identifier on the webcam image

-   The hint on this task question indicate that the tower in sight is indeed Eiffel Tower (which narrows down the location in Paris, France)

![](https://miro.medium.com/v2/resize:fit:845/1*QeuUNyZGNfvYIbDobS1GSQ.png)

The hint given

-   The building is a white coloured observatory (the roof style shows that it is an observatory)

![](https://miro.medium.com/v2/resize:fit:1176/0*IIwGZxN_0L7tEwAq.jpg)

This is what a typical observatory looks like

-   The observatory is located above a hill a bit far away from the city

2) See if there’s any ip address or url linked to the webcam image

-   no (for both of em’)
-   So, we need to link all of the identifiers that we’ve got and Google em’ which is in this case we got Paris observatory (if I put white, Google shows tourist attraction in Paris which not what I want)

![](https://miro.medium.com/v2/resize:fit:1176/1*uvV1lLqtl6Sz2XktGldksQ.png)

So, as you can see there are 2 observatory in Paris. The second one is much more likely to be the location because if it the first one, the Eiffel tower would look bigger in the image because it is much closer to the city center.

To confirm it, we need to open the maps and see the vegetation around the observatory.

3) Open google maps and try to locate the image

![](https://miro.medium.com/v2/resize:fit:845/1*yKqpeJPaDfOVsCZ7k6Z6pw.png)

As you can see the one observatory that closer to the city center look not tally up with the image given

![](https://miro.medium.com/v2/resize:fit:815/1*5w_fbt_GzyscwnFpu8lsuw.png)

so, this is the location of the shot, as you can see the vegetation looks really similar to the image.

Opening the details for the observatory that outside the city, you got Meudon Observatory (In Google, both of them named Paris Observatory but the outer one is located at Meudon)

![](https://miro.medium.com/v2/resize:fit:692/1*l-fJ9VNc9ePuL99FaKVKTw.png)

the google maps detail of the outer city observatory

**_The Answer: Meudon Observatory_**

# Task 7: Your turn, what can you see?

**_The Question: Where is image 4 taken?_**

![](https://miro.medium.com/v2/resize:fit:1176/1*zYi7Le1hhUinjSdy6vHyDA.png)

the 4.png that we will use here

1.  Look for small identifier on the webcam image

-   the car license plate is UK

![](https://miro.medium.com/v2/resize:fit:672/0*j3eh1N3cCkGBzs48.png)

The UK license plate (the one that I use before used to show you that the location is not europe but in this case, the identifier is not there. Re watching this picture, we can see that the identifier is optional so the license plate style is similar to the plate in the picture)

-   A yellow streetlight on both ends
-   A pretty popular zebra crossing in UK because there are webcam of this specific crossing
-   A white pillar holding a black fence
-   Flower at one of the end of the crossing

2) See if there’s any ip address or url linked to the webcam image

So, in this picture there are no ip address and url linked with it.

We need to link the identifier together and google around.

From 1), we can just google “Popular uk zebra crossing”

![](https://miro.medium.com/v2/resize:fit:1176/1*PLZsHoXQhniGTc6vj0Q2VQ.png)

As you can see here, abbey road specifically stated here. So, let us open the abbey road part

![](https://miro.medium.com/v2/resize:fit:1176/1*sJl3YcHtqk8FrltyDttGOw.png)

As you can see from the stock image of Abbey road, it ticks all of the boxes of the identifiers that we gathered before.

3) Open google maps and try to locate the image

To be honest, this is a bit overkill for this question but I am quite confused as of why there are no visible zebra crossing in Google maps?

![](https://miro.medium.com/v2/resize:fit:1176/1*YKQzIZ8LRn7aDvzTwFzF2w.png)

this is what I got from the Google maps. I am confused here but never mind.

**_The Answer: Abbey road_**
<br>
<br>
<br>

![enter image description here](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
