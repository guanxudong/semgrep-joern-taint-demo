package com.tradeflow.services;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/** Session-state snapshot persistence. */
public class SessionStore {

    public Object restore(byte[] blob) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(blob));
        return in.readObject();
    }
}
