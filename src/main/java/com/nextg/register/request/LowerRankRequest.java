package com.nextg.register.request;

import lombok.Data;

@Data
public class LowerRankRequest {
    int curentRank;
    int newRank;
    long userId;
}
