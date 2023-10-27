# Iroh content tracker

This is an example how to write a simple service using mostly iroh-net.
The purpose of this service is to track providers of iroh content.

You can *announce* to a tracker that you believe some host has some content.
The tracker will then periodically *verify* that the content is present.
Finally, you can *query* a tracker for hosts for a content.