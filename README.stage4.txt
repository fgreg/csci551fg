a) No code was reused for this stage.

b) This stage is complete.

c) i) It is statistically load balanced because theoretically we are going to get a random distribution of target IP addresses where the IP is one of the 4294967296 possible addresses. Using MOD breaks this overall space into roughly equal 'buckets' where the number of 'buckets' is equal to the number of routers. So each flow per target is equally likely to end up in one of the buckets.
   ii) Yes
   iii) If we have a large number of active flows that map to the same 'bucket' our load will become unbalanced.